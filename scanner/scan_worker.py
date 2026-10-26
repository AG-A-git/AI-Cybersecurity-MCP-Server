
"""Child-process worker for hard-timeout scanning."""

import multiprocessing


def _scan_worker(file_path, result_queue):
    """Run scanner rules in a child process and return a serializable result."""
    try:
        from scanner.utils import run_all_rules

        result_queue.put(("ok", run_all_rules(file_path)))
    except BaseException as error:
        result_queue.put(
            ("error", type(error).__name__, str(error))
        )


def run_file_with_hard_timeout(
    file_path,
    timeout_seconds,
    worker_target=None,
):
    """Run one file in a child process, terminating it on timeout."""
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    target = worker_target or _scan_worker
    process = context.Process(
        target=target,
        args=(str(file_path), result_queue),
    )

    try:
        process.start()
        process.join(timeout_seconds)

        if process.is_alive():
            process.terminate()
            process.join(timeout=2)

            if process.is_alive() and hasattr(process, "kill"):
                process.kill()
                process.join()

            return "timeout", None

        try:
            result = result_queue.get(timeout=1)
        except Exception:
            return "error", (
                "WorkerError",
                "Worker exited without a result.",
            )

        return result[0], result[1:]

    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)

            if process.is_alive() and hasattr(process, "kill"):
                process.kill()
                process.join()

        result_queue.close()
        result_queue.join_thread()
