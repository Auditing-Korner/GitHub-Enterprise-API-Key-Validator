"""
Progress Tracking Module

Provides progress indicators and better logging for long-running operations.
"""

from typing import Optional, Callable
import sys
import time
from datetime import datetime


class ProgressTracker:
    """Tracks progress of operations."""
    
    def __init__(self, total: int = 0, description: str = "Processing"):
        """
        Initialize progress tracker.
        
        Args:
            total: Total number of items to process
            description: Description of the operation
        """
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = None
        self.items = []
    
    def start(self):
        """Start tracking progress."""
        self.start_time = time.time()
        self.current = 0
    
    def update(self, increment: int = 1, item: Optional[str] = None):
        """
        Update progress.
        
        Args:
            increment: Number of items processed
            item: Optional item description
        """
        self.current += increment
        if item:
            self.items.append(item)
        
        if self.total > 0:
            percentage = (self.current / self.total) * 100
            elapsed = time.time() - self.start_time if self.start_time else 0
            
            if self.current > 0:
                avg_time = elapsed / self.current
                remaining = (self.total - self.current) * avg_time
                eta = f"{remaining:.1f}s" if remaining < 60 else f"{remaining/60:.1f}m"
            else:
                eta = "calculating..."
            
            # Print progress
            sys.stderr.write(f"\r{self.description}: {self.current}/{self.total} ({percentage:.1f}%) - ETA: {eta}")
            sys.stderr.flush()
    
    def finish(self):
        """Finish tracking and print summary."""
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        if self.total > 0:
            sys.stderr.write(f"\r{self.description}: {self.current}/{self.total} (100%) - Completed in {elapsed:.1f}s\n")
        else:
            sys.stderr.write(f"\r{self.description}: Completed in {elapsed:.1f}s\n")
        sys.stderr.flush()
    
    def get_summary(self) -> dict:
        """Get progress summary."""
        elapsed = time.time() - self.start_time if self.start_time else 0
        return {
            "total": self.total,
            "current": self.current,
            "percentage": (self.current / self.total * 100) if self.total > 0 else 0,
            "elapsed": elapsed,
            "items_processed": len(self.items)
        }


class Logger:
    """Enhanced logger with levels and formatting."""
    
    def __init__(self, verbose: bool = False):
        """
        Initialize logger.
        
        Args:
            verbose: Enable verbose logging
        """
        self.verbose = verbose
        self.logs = []
    
    def log(self, message: str, level: str = "INFO"):
        """
        Log a message.
        
        Args:
            message: Message to log
            level: Log level (DEBUG, INFO, WARNING, ERROR)
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "level": level,
            "message": message
        }
        self.logs.append(log_entry)
        
        if level == "ERROR" or self.verbose or level in ["WARNING", "ERROR"]:
            prefix = {
                "DEBUG": "[DEBUG]",
                "INFO": "[INFO]",
                "WARNING": "[WARNING]",
                "ERROR": "[ERROR]"
            }.get(level, "[LOG]")
            
            sys.stderr.write(f"{prefix} {timestamp} - {message}\n")
            sys.stderr.flush()
    
    def debug(self, message: str):
        """Log debug message."""
        self.log(message, "DEBUG")
    
    def info(self, message: str):
        """Log info message."""
        self.log(message, "INFO")
    
    def warning(self, message: str):
        """Log warning message."""
        self.log(message, "WARNING")
    
    def error(self, message: str):
        """Log error message."""
        self.log(message, "ERROR")
    
    def get_logs(self, level: Optional[str] = None) -> list:
        """
        Get logged messages.
        
        Args:
            level: Optional filter by log level
            
        Returns:
            List of log entries
        """
        if level:
            return [log for log in self.logs if log["level"] == level]
        return self.logs


# Global logger instance
_global_logger = Logger()


def get_logger(verbose: bool = False) -> Logger:
    """Get global logger instance."""
    if verbose:
        _global_logger.verbose = True
    return _global_logger

