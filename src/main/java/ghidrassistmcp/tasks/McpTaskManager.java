/*
 * MCP Task Manager for async task execution and tracking.
 */
package ghidrassistmcp.tasks;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import ghidra.util.Msg;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Manages asynchronous MCP task execution and tracking.
 * Provides task submission, status tracking, and cancellation capabilities.
 *
 * <p>Every task runs under a watchdog timeout (default {@link #DEFAULT_TASK_TIMEOUT_SECONDS}s,
 * overridable per-tool via {@link ghidrassistmcp.McpTool#getDefaultTimeoutSeconds()} and per-call
 * via a {@code timeout_seconds} argument, clamped to [{@link #MIN_TASK_TIMEOUT_SECONDS},
 * {@link #MAX_TASK_TIMEOUT_SECONDS}]). This exists because MCP clients (LLM agents) routinely
 * ignore tool-description guidance and fire pathologically slow requests (e.g. "iterate every
 * address in a 30MB binary"); without a backstop such a request pins a worker thread forever.
 *
 * <p>Escalation is two-tier, not a hard kill on every breach: exceeding the timeout only marks
 * the task TIMED_OUT (unblocks the polling caller; the worker keeps running) because forcibly
 * interrupting a Ghidra API call mid-transaction can silently roll back already-applied changes.
 * Only when the worker pool is actually saturated does the watchdog force-cancel every timed-out
 * task to reclaim capacity for new work — i.e. we get more draconian exactly as we approach
 * exhaustion, and stay hands-off otherwise.
 */
public class McpTaskManager {

    private static final int DEFAULT_THREAD_POOL_SIZE = 4;
    private static final int TASK_RETENTION_HOURS = 1;
    private static final int MAX_TERMINAL_TASKS = 200;
    private static final int WATCHDOG_INTERVAL_SECONDS = 5;

    /** Fallback timeout when a tool doesn't override {@link ghidrassistmcp.McpTool#getDefaultTimeoutSeconds()}. */
    public static final int DEFAULT_TASK_TIMEOUT_SECONDS = 30;
    /** Floor for any client-supplied {@code timeout_seconds} override. */
    public static final int MIN_TASK_TIMEOUT_SECONDS = 5;
    /** Ceiling for any client-supplied {@code timeout_seconds} override — "nearly unbounded" but still finite. */
    public static final int MAX_TASK_TIMEOUT_SECONDS = 3600;

    private final Map<String, McpTask> tasks = new ConcurrentHashMap<>();
    private final Map<String, Future<?>> taskFutures = new ConcurrentHashMap<>();
    private final ThreadPoolExecutor executor;
    private final ScheduledExecutorService watchdog;

    /**
     * Create a new task manager with default thread pool size
     */
    public McpTaskManager() {
        this(DEFAULT_THREAD_POOL_SIZE);
    }

    /**
     * Create a new task manager with specified thread pool size
     */
    public McpTaskManager(int threadPoolSize) {
        this.executor = new ThreadPoolExecutor(threadPoolSize, threadPoolSize, 0L, TimeUnit.MILLISECONDS,
            new LinkedBlockingQueue<>(), r -> {
                Thread t = new Thread(r);
                t.setName("MCP-Task-" + t.threadId());
                t.setDaemon(true);
                return t;
            });
        this.watchdog = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "MCP-Task-Watchdog");
            t.setDaemon(true);
            return t;
        });
        this.watchdog.scheduleAtFixedRate(this::sweepTimeouts,
            WATCHDOG_INTERVAL_SECONDS, WATCHDOG_INTERVAL_SECONDS, TimeUnit.SECONDS);
        Msg.info(this, "McpTaskManager initialized with " + threadPoolSize + " threads");
    }

    /**
     * Clamp a client-requested timeout (may be null) to the allowed range, falling back to
     * {@code defaultSeconds} when absent.
     */
    public static int clampTimeoutSeconds(Object requested, int defaultSeconds) {
        int seconds = defaultSeconds;
        if (requested instanceof Number n) {
            seconds = n.intValue();
        } else if (requested instanceof String s) {
            try {
                seconds = Integer.parseInt(s.trim());
            } catch (NumberFormatException ignored) {
                // fall through to defaultSeconds
            }
        }
        return Math.max(MIN_TASK_TIMEOUT_SECONDS, Math.min(MAX_TASK_TIMEOUT_SECONDS, seconds));
    }

    /**
     * Submit a new async task for execution using the default timeout.
     *
     * @param toolName The name of the tool being executed
     * @param arguments The tool arguments
     * @param taskExecutor A supplier that executes the tool and returns the result
     * @return The created task
     */
    public McpTask submitTask(String toolName, Map<String, Object> arguments,
                               Supplier<McpSchema.CallToolResult> taskExecutor) {
        return submitTask(toolName, arguments, DEFAULT_TASK_TIMEOUT_SECONDS, task -> taskExecutor.get());
    }

    public McpTask submitTask(String toolName, Map<String, Object> arguments,
                               McpProgramContext programContext,
                               Supplier<McpSchema.CallToolResult> taskExecutor) {
        return submitTask(toolName, arguments, programContext, task -> taskExecutor.get());
    }

    public McpTask submitTask(String toolName, Map<String, Object> arguments,
                               Function<McpTask, McpSchema.CallToolResult> taskExecutor) {
        return submitTask(toolName, arguments, McpProgramContext.empty(), taskExecutor);
    }

    public McpTask submitTask(String toolName, Map<String, Object> arguments,
                               McpProgramContext programContext,
                               Function<McpTask, McpSchema.CallToolResult> taskExecutor) {
        return submitTask(toolName, arguments, DEFAULT_TASK_TIMEOUT_SECONDS, programContext, taskExecutor);
    }

    public McpTask submitTask(String toolName, Map<String, Object> arguments, int timeoutSeconds,
                               Supplier<McpSchema.CallToolResult> taskExecutor) {
        return submitTask(toolName, arguments, timeoutSeconds, task -> taskExecutor.get());
    }

    /**
     * Submit a new async task for execution with an explicit watchdog timeout.
     *
     * @param timeoutSeconds clamped to [{@link #MIN_TASK_TIMEOUT_SECONDS}, {@link #MAX_TASK_TIMEOUT_SECONDS}]
     */
    public McpTask submitTask(String toolName, Map<String, Object> arguments, int timeoutSeconds,
                               Function<McpTask, McpSchema.CallToolResult> taskExecutor) {
        return submitTask(toolName, arguments, timeoutSeconds, McpProgramContext.empty(), taskExecutor);
    }

    /**
     * Submit a new async task for execution with an explicit watchdog timeout and an immutable
     * snapshot of its target program (captured at submit time, so a later focus change doesn't
     * retroactively change which program a completed task's result is decorated with).
     *
     * @param timeoutSeconds clamped to [{@link #MIN_TASK_TIMEOUT_SECONDS}, {@link #MAX_TASK_TIMEOUT_SECONDS}]
     */
    public McpTask submitTask(String toolName, Map<String, Object> arguments, int timeoutSeconds,
                               McpProgramContext programContext,
                               Function<McpTask, McpSchema.CallToolResult> taskExecutor) {
        // Clean up old tasks before creating new ones
        cleanupOldTasks();

        McpTask task = new McpTask(toolName, arguments, programContext);
        task.setTimeoutSeconds(Math.max(MIN_TASK_TIMEOUT_SECONDS, Math.min(MAX_TASK_TIMEOUT_SECONDS, timeoutSeconds)));
        tasks.put(task.getTaskId(), task);

        Future<?> future = executor.submit(() -> {
            try {
                task.markStarted();
                Msg.info(this, "Task started: " + task.getTaskId() + " for tool: " + toolName);

                McpSchema.CallToolResult result = taskExecutor.apply(task);
                task.markCompleted(result);

                Msg.info(this, "Task completed: " + task.getTaskId() + " in " + task.getDurationMillis() + "ms");

            } catch (Exception e) {
                task.markFailed(e.getMessage());
                Msg.error(this, "Task failed: " + task.getTaskId() + " - " + e.getMessage(), e);
            }
        });

        taskFutures.put(task.getTaskId(), future);
        Msg.info(this, "Task submitted: " + task.getTaskId() + " for tool: " + toolName +
            " (timeout=" + task.getTimeoutSeconds() + "s)");

        return task;
    }

    /**
     * Watchdog sweep: mark overdue tasks TIMED_OUT, and — only once the pool is fully
     * saturated — force-cancel every timed-out task's future to reclaim capacity.
     */
    private void sweepTimeouts() {
        try {
            Instant now = Instant.now();
            for (McpTask task : tasks.values()) {
                if (task.isTerminal()) {
                    continue;
                }
                long elapsedSeconds = ChronoUnit.SECONDS.between(task.getCreatedAt(), now);
                if (elapsedSeconds > task.getTimeoutSeconds()) {
                    task.markTimedOut();
                    Msg.warn(this, "Task timed out: " + task.getTaskId() + " (" + task.getToolName() +
                        ") after " + elapsedSeconds + "s (limit " + task.getTimeoutSeconds() + "s)");
                }
            }

            boolean saturated = executor.getActiveCount() >= executor.getCorePoolSize();
            if (!saturated) {
                return;
            }

            for (McpTask task : tasks.values()) {
                if (task.getStatus() != McpTask.Status.TIMED_OUT) {
                    continue;
                }
                Future<?> future = taskFutures.get(task.getTaskId());
                if (future == null || future.isDone()) {
                    continue;
                }
                future.cancel(true);
                task.markCancelled("Auto-cancelled: exceeded " + task.getTimeoutSeconds() +
                    "s timeout and the worker pool was saturated. If this task's own logic held an open " +
                    "transaction, Ghidra's outer-transaction semantics may roll it back — re-verify any " +
                    "expected changes rather than trusting the task's last progress message.");
                Msg.warn(this, "Task force-cancelled under pool pressure: " + task.getTaskId() +
                    " (" + task.getToolName() + ")");
            }
        } catch (Exception e) {
            Msg.error(this, "Watchdog sweep failed", e);
        }
    }

    /**
     * Get a task by ID
     */
    public McpTask getTask(String taskId) {
        return tasks.get(taskId);
    }

    /**
     * Get task status summary
     */
    public String getTaskStatus(String taskId) {
        McpTask task = tasks.get(taskId);
        if (task == null) {
            return "Task not found: " + taskId;
        }
        return task.toSummary();
    }

    /**
     * Get the result of a completed task
     */
    public McpSchema.CallToolResult getTaskResult(String taskId) {
        McpTask task = tasks.get(taskId);
        if (task == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Task not found: " + taskId)
                .build();
        }

        if (!task.isTerminal()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Task is still running.\n" + task.toSummary())
                .build();
        }

        if (task.getStatus() == McpTask.Status.COMPLETED && task.getResult() != null) {
            return task.getResult();
        }

        if (task.getStatus() == McpTask.Status.FAILED) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Task failed: " + task.getErrorMessage())
                .build();
        }

        if (task.getStatus() == McpTask.Status.CANCELLED) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Task was cancelled: " + task.getProgressMessage())
                .build();
        }

        if (task.getStatus() == McpTask.Status.TIMED_OUT) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Task exceeded its " + task.getTimeoutSeconds() + "s timeout: " +
                    task.getProgressMessage() + " Poll get_task_status again shortly — if the pool " +
                    "later saturates this task will be force-cancelled; otherwise it may still complete " +
                    "and its real result will replace this response. Consider re-running with a smaller " +
                    "scope, or an explicit timeout_seconds argument if the work is legitimately long.")
                .build();
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent("Unknown task state: " + task.getStatus())
            .build();
    }

    /**
     * Cancel a running task
     */
    public boolean cancelTask(String taskId) {
        McpTask task = tasks.get(taskId);
        if (task == null) {
            return false;
        }

        // TIMED_OUT is terminal for client-reporting purposes but the worker may still be
        // running in the background, so an explicit cancel is still meaningful for it.
        if (task.isTerminal() && task.getStatus() != McpTask.Status.TIMED_OUT) {
            return false; // Can't cancel a task that already finished/failed/was cancelled
        }

        Future<?> future = taskFutures.get(taskId);
        if (future != null) {
            future.cancel(true);
        }

        task.markCancelled("Cancelled by client request");
        Msg.info(this, "Task cancelled: " + taskId);
        return true;
    }

    /**
     * List all tasks with optional status filter
     */
    public List<McpTask> listTasks(McpTask.Status statusFilter) {
        cleanupOldTasks();
        if (statusFilter == null) {
            return new ArrayList<>(tasks.values());
        }

        return tasks.values().stream()
            .filter(t -> t.getStatus() == statusFilter)
            .collect(Collectors.toList());
    }

    /**
     * Get a summary of all active tasks
     */
    public String getTasksSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("MCP Tasks Summary:\n\n");

        long pending = tasks.values().stream().filter(t -> t.getStatus() == McpTask.Status.PENDING).count();
        long running = tasks.values().stream().filter(t -> t.getStatus() == McpTask.Status.RUNNING).count();
        long completed = tasks.values().stream().filter(t -> t.getStatus() == McpTask.Status.COMPLETED).count();
        long failed = tasks.values().stream().filter(t -> t.getStatus() == McpTask.Status.FAILED).count();
        long cancelled = tasks.values().stream().filter(t -> t.getStatus() == McpTask.Status.CANCELLED).count();
        long timedOut = tasks.values().stream().filter(t -> t.getStatus() == McpTask.Status.TIMED_OUT).count();

        sb.append("Total: ").append(tasks.size()).append("\n");
        sb.append("  Pending: ").append(pending).append("\n");
        sb.append("  Running: ").append(running).append("\n");
        sb.append("  Completed: ").append(completed).append("\n");
        sb.append("  Failed: ").append(failed).append("\n");
        sb.append("  Cancelled: ").append(cancelled).append("\n");
        sb.append("  TimedOut: ").append(timedOut).append("\n");
        sb.append("Worker pool: ").append(executor.getActiveCount()).append("/")
          .append(executor.getCorePoolSize()).append(" active\n\n");

        if (!tasks.isEmpty()) {
            sb.append("Tasks:\n");
            tasks.values().stream()
                .sorted((a, b) -> b.getCreatedAt().compareTo(a.getCreatedAt())) // Most recent first
                .limit(20) // Limit to 20 most recent
                .forEach(task -> {
                    sb.append("  - ").append(task.getTaskId().substring(0, 8)).append("...")
                      .append(" | ").append(task.getToolName())
                      .append(" | ").append(task.getStatus())
                      .append(" | ").append(task.getProgressPercent()).append("%")
                      .append("\n");
                });
        }

        return sb.toString();
    }

    /**
     * Clean up old completed tasks. Combines time-based eviction (anything older
     * than TASK_RETENTION_HOURS) with a hard size cap (keep at most
     * MAX_TERMINAL_TASKS terminal tasks, dropping oldest first).
     * Running/pending tasks are never evicted.
     */
    private void cleanupOldTasks() {
        Instant cutoff = Instant.now().minus(TASK_RETENTION_HOURS, ChronoUnit.HOURS);

        // Time-based: anything terminal and older than retention. TIMED_OUT tasks have no
        // completedAt (the worker may still be running), so fall back to when the timeout
        // itself elapsed as the reference point.
        List<String> toRemove = tasks.entrySet().stream()
            .filter(e -> e.getValue().isTerminal())
            .filter(e -> effectiveTerminalAt(e.getValue()) != null && effectiveTerminalAt(e.getValue()).isBefore(cutoff))
            .map(Map.Entry::getKey)
            .collect(Collectors.toList());

        // Size-based: if still over the cap after time eviction, drop oldest terminal tasks
        long remainingTerminal = tasks.values().stream()
            .filter(McpTask::isTerminal)
            .count() - toRemove.size();
        if (remainingTerminal > MAX_TERMINAL_TASKS) {
            long excess = remainingTerminal - MAX_TERMINAL_TASKS;
            tasks.entrySet().stream()
                .filter(e -> e.getValue().isTerminal())
                .filter(e -> !toRemove.contains(e.getKey()))
                .filter(e -> effectiveTerminalAt(e.getValue()) != null)
                .sorted((a, b) -> effectiveTerminalAt(a.getValue()).compareTo(effectiveTerminalAt(b.getValue())))
                .limit(excess)
                .map(Map.Entry::getKey)
                .forEach(toRemove::add);
        }

        for (String taskId : toRemove) {
            tasks.remove(taskId);
            taskFutures.remove(taskId);
        }

        if (!toRemove.isEmpty()) {
            Msg.info(this, "Cleaned up " + toRemove.size() + " old tasks");
        }
    }

    /** completedAt if the task finished normally, else (for TIMED_OUT) when its timeout elapsed. */
    private static Instant effectiveTerminalAt(McpTask task) {
        if (task.getCompletedAt() != null) {
            return task.getCompletedAt();
        }
        if (task.getStatus() == McpTask.Status.TIMED_OUT) {
            return task.getCreatedAt().plusSeconds(task.getTimeoutSeconds());
        }
        return null;
    }

    /**
     * Shutdown the task manager
     */
    public void shutdown() {
        Msg.info(this, "Shutting down McpTaskManager...");
        watchdog.shutdownNow();
        executor.shutdown();
        try {
            if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        Msg.info(this, "McpTaskManager shut down");
    }
}
