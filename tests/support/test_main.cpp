// gtest main for the stack tests.
// The stack prints a lot to stdout. To keep the test report readable, the report goes to
// stderr and the stack's stdout goes to a file: $STACK_LOG if set, otherwise /dev/null.

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

namespace
{

class StderrPrinter : public testing::EmptyTestEventListener
{
	void OnTestStart(const testing::TestInfo &t) override
	{
		std::fprintf(stderr, "[ RUN      ] %s.%s\n", t.test_suite_name(), t.name());
	}
	void OnTestPartResult(const testing::TestPartResult &r) override
	{
		if (r.failed())
			std::fprintf(stderr,
				     "%s:%d: Failure\n%s\n",
				     r.file_name() ? r.file_name() : "?",
				     r.line_number(),
				     r.message());
		else if (r.skipped())
			std::fprintf(stderr, "  skipped: %s\n", r.message());
	}
	void OnTestEnd(const testing::TestInfo &t) override
	{
		const char *tag = t.result()->Failed()
				      ? "[  FAILED  ]"
				      : (t.result()->Skipped() ? "[  SKIPPED ]" : "[       OK ]");
		std::fprintf(stderr,
			     "%s %s.%s (%lld ms)\n",
			     tag,
			     t.test_suite_name(),
			     t.name(),
			     (long long)t.result()->elapsed_time());
	}
	void OnTestProgramEnd(const testing::UnitTest &u) override
	{
		std::fprintf(stderr,
			     "\n%d tests, %d passed, %d failed, %d skipped, %d disabled\n",
			     u.test_to_run_count(),
			     u.successful_test_count(),
			     u.failed_test_count(),
			     u.skipped_test_count(),
			     u.disabled_test_count());
		for (int i = 0; i < u.total_test_suite_count(); i++) {
			const testing::TestSuite *s = u.GetTestSuite(i);
			for (int j = 0; j < s->total_test_count(); j++) {
				const testing::TestInfo *t = s->GetTestInfo(j);
				if (t->should_run() && t->result()->Failed())
					std::fprintf(
					    stderr, "  FAILED: %s.%s\n", s->name(), t->name());
			}
		}
	}
};

} // namespace

int main(int argc, char **argv)
{
	bool listing = false; // ctest discovers tests via --gtest_list_tests on stdout
	for (int i = 1; i < argc; i++)
		if (std::string(argv[i]).rfind("--gtest_list_tests", 0) == 0)
			listing = true;

	testing::InitGoogleTest(&argc, argv);
	if (listing)
		return RUN_ALL_TESTS();

	const char *log = std::getenv("STACK_LOG");
	if (!std::freopen(log ? log : "/dev/null", "w", stdout))
		std::perror("redirecting stdout");
	setvbuf(stdout, nullptr, _IOFBF, 1 << 16);

	testing::TestEventListeners &l = testing::UnitTest::GetInstance()->listeners();
	delete l.Release(l.default_result_printer());
	l.Append(new StderrPrinter);

	return RUN_ALL_TESTS();
}
