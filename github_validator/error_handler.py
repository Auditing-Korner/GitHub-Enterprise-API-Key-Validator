"""
Enhanced Error Handling Module

Provides detailed error messages, error categorization, and error reporting.
"""

from typing import Dict, List, Optional, Any, Tuple
import traceback
import sys


class ErrorHandler:
    """Handles errors with detailed messages and categorization."""
    
    # Error categories
    ERROR_CATEGORIES = {
        "authentication": ["401", "403", "Unauthorized", "Forbidden", "Bad credentials"],
        "rate_limit": ["429", "rate limit", "X-RateLimit"],
        "not_found": ["404", "Not Found"],
        "permission": ["403", "Forbidden", "permission", "access denied"],
        "network": ["Connection", "Timeout", "DNS", "network"],
        "api_error": ["500", "502", "503", "504", "Internal Server Error"],
        "validation": ["400", "Bad Request", "validation", "invalid"],
        "timeout": ["timeout", "timed out", "Timeout"]
    }
    
    def __init__(self):
        self.error_log = []
        self.error_counts = {}
    
    def categorize_error(self, error: Exception) -> str:
        """
        Categorize an error based on its message or type.
        
        Args:
            error: Exception object
            
        Returns:
            Error category string
        """
        error_str = str(error).lower()
        error_type = type(error).__name__
        
        # Check error message
        for category, keywords in self.ERROR_CATEGORIES.items():
            for keyword in keywords:
                if keyword.lower() in error_str:
                    return category
        
        # Check error type
        if "HTTPError" in error_type or "RequestException" in error_type:
            return "network"
        elif "Timeout" in error_type:
            return "timeout"
        elif "ValueError" in error_type or "TypeError" in error_type:
            return "validation"
        else:
            return "unknown"
    
    def format_error_message(self, error: Exception, context: Optional[str] = None) -> Dict[str, Any]:
        """
        Format a detailed error message.
        
        Args:
            error: Exception object
            context: Optional context about where the error occurred
            
        Returns:
            Dictionary with formatted error information
        """
        category = self.categorize_error(error)
        error_type = type(error).__name__
        error_message = str(error)
        
        # Get traceback
        tb_str = traceback.format_exc() if sys.exc_info()[0] else ""
        
        # Generate user-friendly message
        user_message = self._generate_user_message(category, error_message, context)
        
        # Generate suggestions
        suggestions = self._generate_suggestions(category, error_message)
        
        error_info = {
            "category": category,
            "type": error_type,
            "message": error_message,
            "user_message": user_message,
            "context": context,
            "suggestions": suggestions,
            "traceback": tb_str
        }
        
        # Log error
        self.error_log.append(error_info)
        self.error_counts[category] = self.error_counts.get(category, 0) + 1
        
        return error_info
    
    def _generate_user_message(self, category: str, error_message: str, context: Optional[str] = None) -> str:
        """Generate user-friendly error message."""
        base_messages = {
            "authentication": "Authentication failed. Please check your API key/token.",
            "rate_limit": "Rate limit exceeded. Please wait before making more requests.",
            "not_found": "Resource not found. The requested resource may not exist or you may not have access.",
            "permission": "Permission denied. Your API key may not have the required permissions.",
            "network": "Network error occurred. Please check your internet connection.",
            "api_error": "GitHub API error. The service may be temporarily unavailable.",
            "validation": "Invalid input or request format.",
            "timeout": "Request timed out. The operation took too long to complete.",
            "unknown": "An unexpected error occurred."
        }
        
        message = base_messages.get(category, base_messages["unknown"])
        
        if context:
            message = f"{message} (Context: {context})"
        
        return message
    
    def _generate_suggestions(self, category: str, error_message: str) -> List[str]:
        """Generate helpful suggestions based on error category."""
        suggestions_map = {
            "authentication": [
                "Verify your API key is correct and not expired",
                "Check if the API key has the required scopes",
                "Ensure you're using the correct base URL for GitHub Enterprise"
            ],
            "rate_limit": [
                "Wait for the rate limit to reset",
                "Use a token with higher rate limits",
                "Implement exponential backoff in your requests"
            ],
            "not_found": [
                "Verify the resource name/path is correct",
                "Check if you have access to the resource",
                "Ensure the resource exists in the organization"
            ],
            "permission": [
                "Review your API key permissions",
                "Request additional scopes if needed",
                "Check organization/enterprise access policies"
            ],
            "network": [
                "Check your internet connection",
                "Verify GitHub API is accessible",
                "Check firewall/proxy settings"
            ],
            "api_error": [
                "Retry the request after a short delay",
                "Check GitHub status page for service issues",
                "Verify your request format is correct"
            ],
            "timeout": [
                "Increase the timeout value",
                "Check network connectivity",
                "Reduce the amount of data requested"
            ]
        }
        
        return suggestions_map.get(category, ["Review the error details and try again"])
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of all logged errors."""
        return {
            "total_errors": len(self.error_log),
            "error_counts": self.error_counts,
            "errors_by_category": {
                category: [e for e in self.error_log if e["category"] == category]
                for category in set(e["category"] for e in self.error_log)
            }
        }
    
    def clear_errors(self):
        """Clear error log."""
        self.error_log = []
        self.error_counts = {}


# Global error handler instance
_global_error_handler = ErrorHandler()


def handle_error(error: Exception, context: Optional[str] = None) -> Dict[str, Any]:
    """
    Handle an error using the global error handler.
    
    Args:
        error: Exception object
        context: Optional context
        
    Returns:
        Formatted error information
    """
    return _global_error_handler.format_error_message(error, context)


def get_error_summary() -> Dict[str, Any]:
    """Get error summary from global error handler."""
    return _global_error_handler.get_error_summary()

