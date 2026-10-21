// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_util.h>
#include "minunit.h"

#define SLOW_BUF_SIZE  0x40000
#define PATTERN_PERIOD 0x1000
#define SLOW_N_HITS    (SLOW_BUF_SIZE / PATTERN_PERIOD)
// makes the search last about 640 ms, much longer than the cancel check interval
#define SLOW_READ_USEC_PER_KIB 2500

typedef struct {
	ut64 offset;
} SlowBufCtx;

typedef struct {
	size_t n_calls;
	bool cancel;
} CancelCtx;

static bool slow_buf_init(RzBuffer *b, const void *user) {
	b->priv = (void *)user;
	return true;
}

static st64 slow_buf_seek(RzBuffer *b, st64 addr, int whence) {
	SlowBufCtx *ctx = b->priv;
	ctx->offset = rz_seek_offset(ctx->offset, SLOW_BUF_SIZE, addr, whence);
	return ctx->offset;
}

static ut64 slow_buf_get_size(RzBuffer *b) {
	return SLOW_BUF_SIZE;
}

static st64 slow_buf_read(RzBuffer *b, ut8 *buf, ut64 len) {
	SlowBufCtx *ctx = b->priv;
	ut64 size = ctx->offset < SLOW_BUF_SIZE ? RZ_MIN(len, SLOW_BUF_SIZE - ctx->offset) : 0;
	rz_sys_usleep(SLOW_READ_USEC_PER_KIB * (size / 1024));
	for (ut64 i = 0; i < size; i++) {
		buf[i] = (ctx->offset + i) % PATTERN_PERIOD ? 0 : 'R';
	}
	ctx->offset += size;
	return size;
}

static const RzBufferMethods slow_buf_methods = {
	.init = slow_buf_init,
	.read = slow_buf_read,
	.get_size = slow_buf_get_size,
	.seek = slow_buf_seek,
};

static bool count_cancel_cb(void *user, size_t n_hits, RzSearchCancelReason invoke_reason) {
	CancelCtx *ctx = user;
	ctx->n_calls++;
	return ctx->cancel;
}

static RzList /*<RzSearchHit *>*/ *slow_search(CancelCtx *cancel_ctx) {
	SlowBufCtx buf_ctx = { 0 };
	RzBuffer *buf = rz_buf_new_with_methods(&slow_buf_methods, &buf_ctx, RZ_BUFFER_CUSTOM);
	RzSearchOpt *opt = rz_search_opt_new();
	RzSearchCollection *col = rz_search_collection_bytes();
	RzList *hits = NULL;
	if (buf && opt && col &&
		rz_search_opt_set_find_options(opt, rz_search_find_opt_new()) &&
		rz_search_opt_get_find_options(opt) &&
		rz_search_opt_set_max_threads(opt, 1) &&
		rz_search_opt_set_chunk_size(opt, 1) &&
		rz_search_opt_set_show_progress_from_str(opt, "false") &&
		rz_search_opt_set_cancel_cb(opt, count_cancel_cb, cancel_ctx) &&
		rz_search_collection_bytes_add(col, "R", (const ut8 *)"R", (const ut8 *)"\xff", 1)) {
		hits = rz_search_on_buffer(opt, col, buf, NULL);
	}
	rz_search_collection_free(col);
	rz_search_opt_free(opt);
	rz_buf_free(buf);
	return hits;
}

static bool test_search_cancel_cb_regular_check(void) {
	CancelCtx cancel_ctx = { 0 };
	RzList *hits = slow_search(&cancel_ctx);
	mu_assert_notnull(hits, "search failed");
	size_t n_hits = rz_list_length(hits);
	rz_list_free(hits);
	mu_assert_eq(n_hits, SLOW_N_HITS, "hits");
	mu_assert_true(cancel_ctx.n_calls > 1, "cancel callback is called during the search");
	mu_end;
}

static bool test_search_cancel(void) {
	CancelCtx cancel_ctx = { .cancel = true };
	RzList *hits = slow_search(&cancel_ctx);
	mu_assert_notnull(hits, "search failed");
	size_t n_hits = rz_list_length(hits);
	rz_list_free(hits);
	mu_assert_eq(cancel_ctx.n_calls, 1, "cancel callback calls");
	mu_assert_true(n_hits < SLOW_N_HITS, "search stops when cancelled");
	mu_end;
}

int all_tests() {
	mu_run_test(test_search_cancel_cb_regular_check);
	mu_run_test(test_search_cancel);
	return tests_passed != tests_run;
}

mu_main(all_tests)
