#include "byte_ring_buffers.h"
#include "tcp_segment.h"
#include <arpa/inet.h>

static void insert_ooo_segment(struct byte_reassembly_rcv_buffer *b,
			       struct ooo_seg seg,
			       size_t idx);

struct byte_reassembly_rcv_buffer *create_byte_rcv_buffer(size_t capacity)
{
	// enforce only power of 2 sizes
	if (capacity == 0 || (capacity & (capacity - 1)) != 0)
		return NULL;

	struct byte_reassembly_rcv_buffer *b = malloc(sizeof(*b));
	if (!b)
		return NULL;

	b->data = malloc(capacity);
	if (!b->data) {
		free(b);
		return NULL;
	}

	b->capacity = capacity;
	b->ooo_count = 0;
	b->ooo_capacity = MAX_OOO_RCV_SEG_STORED;
	b->fin_received = false;
	b->contiguous_bytes = 0;
	b->head = 0;
	b->tail = 0;

	pthread_mutex_init(&b->lock, NULL);
	pthread_cond_init(&b->cond, NULL);

	return b;
}

void destroy_byte_rcv_buffer(struct byte_reassembly_rcv_buffer *b)
{
	if (!b)
		return;

	pthread_mutex_destroy(&b->lock);
	pthread_cond_destroy(&b->cond);

	free(b->data);
	free(b);
}

struct byte_snd_buffer *create_byte_snd_buffer(size_t capacity)
{
	// enforce only power of 2 sizes
	if (capacity == 0 || (capacity & (capacity - 1)) != 0)
		return NULL;

	struct byte_snd_buffer *b = malloc(sizeof(*b));
	if (!b)
		return NULL;

	b->data = malloc(capacity);
	if (!b->data) {
		free(b);
		return NULL;
	}
	b->capacity = capacity;

	if (pthread_mutex_init(&b->lock, NULL) < 0)
		return NULL;
	if (pthread_cond_init(&b->cond, NULL) < 0)
		return NULL;

	b->rcov_mode = false;
	b->sack_blocks_count = 0;
	memset(b->sack_blocks, 0, sizeof(b->sack_blocks));
	b->sacked_bytes = 0;

	b->used_bytes = 0;
	b->head = 0;
	b->snd_nxt_i = 0;
	b->tail = 0;
	b->used_bytes = 0;
	memset(b->ctrl, 0, sizeof(b->ctrl));
	b->ctrl_count = 0;

	return b;
}

void destroy_byte_snd_buffer(struct byte_snd_buffer *b)
{
	if (!b)
		return;

	pthread_mutex_destroy(&b->lock);
	pthread_cond_destroy(&b->cond);

	free(b->data);
	free(b);
}

size_t write_to_snd_buff(struct byte_snd_buffer *b, unsigned char *data, size_t len)
{
	if (!b || !data || len == 0)
		return 0;

	lock_snd_buff(b);
	size_t available = sndbuff_available_space(b);
	if (len > available)
		len = available;

	// if writing would cross the end of the buffer, split into two parts.
	size_t first_part = len;
	if (b->tail + len > b->capacity) {
		first_part = b->capacity - b->tail;
	}
	if (first_part < len) {
		memcpy(b->data + b->tail, data, first_part);
		memcpy(b->data, data + first_part, len - first_part);
	} else {
		memcpy(b->data + b->tail, data, len);
	}

	b->tail = (b->tail + len) & (b->capacity - 1);
	b->used_bytes += len;

	unlock_snd_buff(b);
	return len;
}

// writes raw bytes into receive buffer at a physical index.
// does not update any metadata fields (head, contiguous_bytes, rcv_nxt, ...)
static size_t write_to_rcv_buff(struct byte_reassembly_rcv_buffer *b,
				size_t start_index,
				const unsigned char *data,
				size_t len)
{
	if (!b || !data || len == 0)
		return 0;

	size_t first_part = len;
	if (start_index + len > b->capacity) {
		first_part = b->capacity - start_index;
	}
	if (first_part < len) {
		memcpy(b->data + start_index, data, first_part);
		memcpy(b->data, data + first_part, len - first_part);
	} else {
		memcpy(b->data + start_index, data, len);
	}

	return len;
}

// returns index of first element in ooo_segs whose .seq is equal to or comes after seq
size_t bin_search_seq_after_eq_indx(uint32_t seq, struct byte_reassembly_rcv_buffer *b)
{
	size_t lo = 0;
	size_t hi = b->ooo_count;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		if (tcp_seq_after_eq(b->ooo_segs[mid].start_seq, seq))
			hi = mid;
		else
			lo = mid + 1;
	}
	return lo;
}

// writes data to rcv buff, not overwriting already written ooo segments
// "first arrival wins"
// when inserting ooo segment, provide ooo_i so we can use it afterwards to insert ooo_seg
// caller must hold lock
static size_t write_unwritten_bytes(struct byte_reassembly_rcv_buffer *b,
				    uint32_t seq_start,
				    uint32_t seq_end,
				    const unsigned char *data,
				    size_t *ooo_i)
{
	size_t written = 0;

	uint32_t current_start = seq_start;
	uint32_t current_end = seq_end;

	size_t data_offset;
	size_t data_len;

	size_t i = bin_search_seq_after_eq_indx(seq_start, b);

	if (ooo_i)
		*ooo_i = i;

	// potential overlapping ooo seg found
	if (i != b->ooo_count) {
		// check previous one, might overlap as well due to length
		if (i != 0) {
			uint32_t ooo_end = b->ooo_segs[i - 1].end_seq;
			// trim left
			if (tcp_seq_before_eq(current_start, ooo_end))
				current_start = ooo_end;
		}

		// go through all ooo segs up until seq_end
		for (; tcp_seq_before(b->ooo_segs[i].start_seq, seq_end); i++) {
			// trim right
			current_end = b->ooo_segs[i].start_seq;
			data_offset = current_start - seq_start;
			data_len = current_end - current_start;
			size_t physical_idx = seq_to_index(b, current_start);
			written += write_to_rcv_buff(b, physical_idx, data + data_offset, data_len);

			// new writing start after current ooo block
			current_start = b->ooo_segs[i].end_seq;
			// new writing start overshoots new data's end, all done
			if (tcp_seq_after(current_start, seq_end))
				return written;
		}
	}

	// write all remaining new bytes
	data_offset = current_start - seq_start;
	data_len = current_end - current_start;
	size_t physical_idx = seq_to_index(b, current_start);
	written += write_to_rcv_buff(b, physical_idx, data + data_offset, data_len);
	return written;
}

// only called when segment is (partly) within receive buffer
// writes a tcp segment into the receive buffer, either contigously or leaves appropriate gap space
// if segment is out of order keeps track of ooo_segments metadata, merges if possible "first
// arrival wins", bytes are never overwritten returns the number of bytes written
size_t rcv_buffer_write_tcp_segment(struct byte_reassembly_rcv_buffer *b, struct tcp_segment *seg)
{
	if (!b || !seg || seg->payload_len == 0)
		return 0;

	lock_rcv_buff(b);

	uint32_t seg_seq = ntohl(seg->header->seq_num);
	uint32_t data_seq = seg_seq; // data starts at seq; SYN/FIN handled at TCP layer
	uint32_t rcv_nxt = b->rcv_nxt;
	size_t data_len = seg->payload_len;
	const unsigned char *data = seg->payload;
	size_t written = 0;

	// left-trim any part of the payload that is before rcv_nxt
	if (tcp_seq_before(data_seq, rcv_nxt)) {
		uint32_t delta = rcv_nxt - data_seq;
		data += delta;
		data_len -= delta;
		data_seq = rcv_nxt;
	}

	// right-trim any part of the payload exceeding right edge of receive window
	uint32_t wndw_right_edge = rcv_nxt + b->rcv_wnd;
	if (tcp_seq_after_eq(data_seq + data_len, wndw_right_edge)) {
		uint32_t delta = (data_seq + data_len) - wndw_right_edge;
		data_len -= delta;
	}

	// in order data
	if (data_seq == rcv_nxt) {
		// Fill all gaps in [rcv_nxt, rcv_nxt + min(data_len, available)) that
		// are not already covered by OOO
		written += write_unwritten_bytes(b, data_seq, data_seq + data_len, data, NULL);
		b->contiguous_bytes += data_len;
		update_rcv_nxt_tail(b, data_len);
		// check if OOO ranges have become fully or partly overtaken by contiguous data
		while (b->ooo_count > 0) {
			uint32_t seg_start = b->ooo_segs[0].start_seq;
			uint32_t seg_end = b->ooo_segs[0].end_seq;

			// still a gap
			if (tcp_seq_after(seg_start, b->rcv_nxt))
				break;

			// rcv_next now falls within an ooo seg
			// this ooo seg now also contiguous, adjust rcv_next
			if (tcp_seq_after(seg_end, b->rcv_nxt) &&
			    tcp_seq_before_eq(seg_start, b->rcv_nxt)) {
				uint32_t delta = b->rcv_nxt - seg_start;
				size_t seg_len = seg_end - seg_start;
				update_rcv_nxt_tail(b, seg_len - delta);
				b->contiguous_bytes += seg_len - delta;
			}

			// drop obsolete metadata //
			memmove(&b->ooo_segs[0],
				&b->ooo_segs[1],
				(b->ooo_count - 1) * sizeof(b->ooo_segs[0]));
			b->ooo_count--;
		}
	} else {
		// out-of-order segment (data_seq > rcv_nxt)

		// only process if there's free space in ooo_segs, OR if current segment is not a
		// separate ooo_seg after the last stored one. We
		// prioritise storing earlier segs over later ones
		if (b->ooo_count != b->ooo_capacity ||
		    tcp_seq_before_eq(data_seq, b->ooo_segs[b->ooo_capacity - 1].end_seq)) {
			size_t ooo_i;

			written +=
			    write_unwritten_bytes(b, data_seq, data_seq + data_len, data, &ooo_i);
			struct ooo_seg seg = {.start_seq = data_seq,
					      .end_seq = data_seq + data_len};
			insert_ooo_segment(b, seg, ooo_i);
		}
	}

	unlock_rcv_buff(b);
	return written;
}

static void merge_next_ooo_segs(struct byte_reassembly_rcv_buffer *b, size_t idx)
{
	if (idx == b->ooo_count - 1)
		return;

	while (b->ooo_count > 0 && idx + 1 < b->ooo_count) {
		uint32_t cur_end = b->ooo_segs[idx].end_seq;
		uint32_t nxt_start = b->ooo_segs[idx + 1].start_seq;
		uint32_t nxt_end = b->ooo_segs[idx + 1].end_seq;

		// can merge
		if (tcp_seq_before_eq(nxt_start, cur_end)) {
			if (tcp_seq_after(nxt_end, cur_end))
				b->ooo_segs[idx].end_seq = nxt_end;

			memmove(&b->ooo_segs[idx + 1],
				&b->ooo_segs[idx + 2],
				(b->ooo_count - (idx + 2)) * sizeof(struct ooo_seg));
			b->ooo_count--;
		} else
			break;
	}
	return;
}

// insert ooo into ordered array at index, caller must hold lock
static void insert_ooo_segment(struct byte_reassembly_rcv_buffer *b, struct ooo_seg seg, size_t idx)
{
	uint32_t new_start = seg.start_seq;
	uint32_t new_end = seg.end_seq;

	if (idx > 0) {
		uint32_t prev_end = b->ooo_segs[idx - 1].end_seq;

		// merge into the previous segment if overlaps or touches (modulo 32-bit)
		if (tcp_seq_before_eq(new_start, prev_end)) {
			// ooo_segs = [1, 4), [5, 8)
			// insert [4, 6) at index 1
			if (tcp_seq_after(new_end, prev_end)) {
				// => [1, 6), [5, 8)
				b->ooo_segs[idx - 1].end_seq = new_end;
				// then merge [5, 8) into [1, 6)
				merge_next_ooo_segs(b, idx - 1);
			}
			return;
		}
	}

	if (idx < b->ooo_count) {
		uint32_t next_start = b->ooo_segs[idx].start_seq;
		uint32_t next_end = b->ooo_segs[idx].end_seq;
		// merge into next element if overlaps or touches next
		if (tcp_seq_after_eq(new_end, next_start)) {
			// ooo_segs = [1, 4), [8, 10), ...
			// insert [7, 12) at index => [1, 4), [7, x), ...
			b->ooo_segs[idx].start_seq = new_start;
			if (tcp_seq_after(new_end, next_end)) {
				// => [1, 4), [7, 12), ...
				b->ooo_segs[idx].end_seq = new_end;
				// then merge nexts into [7, 12)
				merge_next_ooo_segs(b, idx);
			}
			return;
		}
	}

	// no merging with prev or next, insert fully new block
	size_t shifts = b->ooo_count - idx;
	if (b->ooo_count == b->ooo_capacity && shifts != 0)
		shifts--;
	if (shifts > 0)
		memmove(&b->ooo_segs[idx + 1], &b->ooo_segs[idx], shifts * sizeof(struct ooo_seg));

	b->ooo_count += b->ooo_count == b->ooo_capacity ? 0 : 1;
	b->ooo_segs[idx] = seg;
}
