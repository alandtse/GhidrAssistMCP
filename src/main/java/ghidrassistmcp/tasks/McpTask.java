/*
 * MCP Task state object for async task management.
 */
package ghidrassistmcp.tasks;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import io.modelcontextprotocol.spec.McpSchema;

/**
 * Represents an asynchronous MCP task with its state and result.
 */
public class McpTask {

    /**
     * Task status enumeration
     */
    public enum Status {
        PENDING,    // Task is queued but not yet started
        RUNNING,    // Task is currently executing
        COMPLETED,  // Task completed successfully
        FAILED,     // Task failed with an error
        CANCELLED,  // Task was cancelled (explicitly, or auto-cancelled by the watchdog under pool pressure)
        TIMED_OUT   // Task exceeded its watchdog timeout; the caller has been unblocked but the
                    // worker thread may still be running in the background unless/until the pool
                    // becomes saturated and the watchdog force-cancels it
    }

    private final String taskId;
    private final String toolName;
    private final Map<String, Object> arguments;
    private final Instant createdAt;
    private volatile Status status;
    private volatile Instant startedAt;
    private volatile Instant completedAt;
    private volatile McpSchema.CallToolResult result;
    private volatile String errorMessage;
    private volatile int progressPercent;
    private volatile String progressMessage;
    private volatile int timeoutSeconds;

    /**
     * Create a new task
     */
    public McpTask(String toolName, Map<String, Object> arguments) {
        this.taskId = UUID.randomUUID().toString();
        this.toolName = toolName;
        this.arguments = arguments;
        this.createdAt = Instant.now();
        this.status = Status.PENDING;
        this.progressPercent = 0;
        this.progressMessage = "Waiting to start...";
    }

    // Getters

    public String getTaskId() {
        return taskId;
    }

    public String getToolName() {
        return toolName;
    }

    public Map<String, Object> getArguments() {
        return arguments;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Status getStatus() {
        return status;
    }

    public Instant getStartedAt() {
        return startedAt;
    }

    public Instant getCompletedAt() {
        return completedAt;
    }

    public McpSchema.CallToolResult getResult() {
        return result;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public int getProgressPercent() {
        return progressPercent;
    }

    public String getProgressMessage() {
        return progressMessage;
    }

    public int getTimeoutSeconds() {
        return timeoutSeconds;
    }

    public void setTimeoutSeconds(int timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
    }

    // State transition methods

    /**
     * Mark task as started
     */
    public synchronized void markStarted() {
        if (this.status == Status.PENDING) {
            this.status = Status.RUNNING;
            this.startedAt = Instant.now();
            this.progressMessage = "Running...";
        }
    }

    /**
     * Update task progress
     */
    public synchronized void updateProgress(int percent, String message) {
        if (this.status == Status.RUNNING) {
            this.progressPercent = Math.max(0, Math.min(100, percent));
            this.progressMessage = message;
        }
    }

    /**
     * Mark task as completed with result. Still allowed from TIMED_OUT so a task that
     * finishes late (after the watchdog already unblocked the caller) records its real
     * outcome rather than being silently discarded.
     */
    public synchronized void markCompleted(McpSchema.CallToolResult taskResult) {
        if (this.status == Status.RUNNING || this.status == Status.PENDING || this.status == Status.TIMED_OUT) {
            this.status = Status.COMPLETED;
            this.completedAt = Instant.now();
            this.result = taskResult;
            this.progressPercent = 100;
            this.progressMessage = "Completed";
        }
    }

    /**
     * Mark task as failed with error
     */
    public synchronized void markFailed(String taskErrorMessage) {
        if (this.status == Status.RUNNING || this.status == Status.PENDING || this.status == Status.TIMED_OUT) {
            this.status = Status.FAILED;
            this.completedAt = Instant.now();
            this.errorMessage = taskErrorMessage;
            this.progressMessage = "Failed: " + taskErrorMessage;
        }
    }

    /**
     * Mark task as cancelled
     */
    public synchronized void markCancelled() {
        markCancelled("Cancelled");
    }

    /**
     * Mark task as cancelled with a specific reason (e.g. auto-cancelled by the watchdog).
     */
    public synchronized void markCancelled(String reason) {
        if (this.status == Status.PENDING || this.status == Status.RUNNING || this.status == Status.TIMED_OUT) {
            this.status = Status.CANCELLED;
            this.completedAt = Instant.now();
            this.progressMessage = reason;
        }
    }

    /**
     * Mark task as having exceeded its watchdog timeout. Soft marker only: the underlying
     * worker thread is NOT interrupted here (forcefully interrupting Ghidra API calls mid-flight
     * can trigger a silent transaction rollback), it just tells the caller not to keep waiting.
     * The task may still transition to COMPLETED/FAILED later, or to CANCELLED if the pool
     * later saturates and the watchdog force-reclaims it.
     */
    public synchronized void markTimedOut() {
        if (this.status == Status.PENDING || this.status == Status.RUNNING) {
            this.status = Status.TIMED_OUT;
            this.progressMessage = "Exceeded " + timeoutSeconds + "s timeout; still running in the " +
                "background unless the worker pool saturates and forces cancellation.";
        }
    }

    /**
     * Check if task is terminal (completed, failed, cancelled, or timed out)
     */
    public boolean isTerminal() {
        Status s = this.status;
        return s == Status.COMPLETED || s == Status.FAILED || s == Status.CANCELLED || s == Status.TIMED_OUT;
    }

    /**
     * Get duration in milliseconds (or elapsed time if still running)
     */
    public long getDurationMillis() {
        if (startedAt == null) {
            return 0;
        }
        Instant end = completedAt != null ? completedAt : Instant.now();
        return end.toEpochMilli() - startedAt.toEpochMilli();
    }

    /**
     * Generate a summary string for display
     */
    public String toSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Task ID: ").append(taskId).append("\n");
        sb.append("Tool: ").append(toolName).append("\n");
        sb.append("Status: ").append(status).append("\n");
        sb.append("Progress: ").append(progressPercent).append("% - ").append(progressMessage).append("\n");
        sb.append("Timeout: ").append(timeoutSeconds).append("s\n");
        sb.append("Created: ").append(createdAt).append("\n");

        if (startedAt != null) {
            sb.append("Started: ").append(startedAt).append("\n");
        }

        if (completedAt != null) {
            sb.append("Completed: ").append(completedAt).append("\n");
            sb.append("Duration: ").append(getDurationMillis()).append("ms\n");
        }

        if (errorMessage != null) {
            sb.append("Error: ").append(errorMessage).append("\n");
        }

        return sb.toString();
    }
}
