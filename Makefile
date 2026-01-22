SRC_DIR = src
BUILD_DIR = build

CC = gcc
CFLAGS = -Wall -Wextra -MMD -MP

C_FILES = $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES = $(C_FILES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

.PHONY: all clean

all: networking.elf

networking.elf: $(OBJ_FILES)
	$(CC) -o $@ $^

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

-include $(OBJ_FILES:.o=.d)

clean:
	rm -f $(BUILD_DIR)/*.o $(BUILD_DIR)/*.d networking.elf
