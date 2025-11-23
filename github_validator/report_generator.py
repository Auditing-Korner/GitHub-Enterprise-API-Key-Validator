"""
HTML Report Generator Module

Generates comprehensive HTML security reports from analysis findings.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
import json
import os
from .risk_scorer import RiskScorer


class HTMLReportGenerator:
    """Generates HTML security reports from analysis findings."""
    
    def __init__(self):
        self.template = self._load_template()
    
    def _load_template(self) -> str:
        """Load the HTML template."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitHub API Key Security Analysis Report - RFS</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif;
            line-height: 1.7;
            color: #1a2332;
            background: linear-gradient(135deg, #e8f0f7 0%, #f0f4f8 50%, #e8f0f7 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            overflow: hidden;
        }}
        header {{
            background: linear-gradient(135deg, #0f2027 0%, #203a43 25%, #2c5364 50%, #203a43 75%, #0f2027 100%);
            color: white;
            padding: 50px 40px;
            text-align: center;
            position: relative;
            overflow: hidden;
            box-shadow: 0 4px 20px rgba(15, 32, 39, 0.3);
        }}
        header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1440 320"><path fill="rgba(255,255,255,0.05)" d="M0,96L48,112C96,128,192,160,288,160C384,160,480,128,576,122.7C672,117,768,139,864,154.7C960,171,1056,181,1152,165.3C1248,149,1344,107,1392,85.3L1440,64L1440,320L1392,320C1344,320,1248,320,1152,320C1056,320,960,320,864,320C768,320,672,320,576,320C480,320,384,320,288,320C192,320,96,320,48,320L0,320Z"></path></svg>') no-repeat bottom;
            background-size: cover;
            opacity: 0.3;
        }}
        header > * {{
            position: relative;
            z-index: 1;
        }}
        header h1 {{
            font-size: 2.8em;
            margin-bottom: 15px;
            font-weight: 700;
            letter-spacing: -0.5px;
            text-shadow: 0 2px 10px rgba(0,0,0,0.2);
        }}
        header .subtitle {{
            font-size: 1.1em;
            opacity: 0.95;
            margin-top: 10px;
            font-weight: 300;
        }}
        header .author {{
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid rgba(255,255,255,0.2);
            font-size: 0.95em;
            opacity: 0.9;
        }}
        .content {{ padding: 50px 40px; }}
        .alert {{
            padding: 20px 25px;
            border-radius: 10px;
            margin: 25px 0;
            border-left: 5px solid;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }}
        .alert-critical {{
            background: linear-gradient(135deg, #fff1f2 0%, #ffe4e6 50%, #fecdd3 100%);
            border-color: #dc2626;
            color: #7f1d1d;
            box-shadow: 0 2px 8px rgba(220, 38, 38, 0.15);
        }}
        .alert-high {{
            background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 50%, #fde68a 100%);
            border-color: #f59e0b;
            color: #78350f;
            box-shadow: 0 2px 8px rgba(245, 158, 11, 0.15);
        }}
        .alert-medium {{
            background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 50%, #bfdbfe 100%);
            border-color: #3b82f6;
            color: #1e3a8a;
            box-shadow: 0 2px 8px rgba(59, 130, 246, 0.15);
        }}
        .alert-info {{
            background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 50%, #bbf7d0 100%);
            border-color: #10b981;
            color: #064e3b;
            box-shadow: 0 2px 8px rgba(16, 185, 129, 0.15);
        }}
        section {{
            margin: 50px 0;
            padding: 35px;
            background: linear-gradient(135deg, #ffffff 0%, #fafbfc 100%);
            border-radius: 12px;
            border-left: 5px solid #0f2027;
            box-shadow: 0 4px 16px rgba(15, 32, 39, 0.08);
            transition: box-shadow 0.3s;
        }}
        section:hover {{
            box-shadow: 0 6px 24px rgba(15, 32, 39, 0.12);
        }}
        section h2 {{
            color: #0f2027;
            font-size: 2.2em;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 3px solid #e2e8f0;
            font-weight: 700;
            background: linear-gradient(135deg, #0f2027 0%, #2c5364 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        section h3 {{
            color: #1e293b;
            font-size: 1.6em;
            margin-top: 30px;
            margin-bottom: 18px;
            font-weight: 600;
        }}
        section h4 {{
            color: #555;
            font-size: 1.2em;
            margin-top: 20px;
            margin-bottom: 12px;
            font-weight: 600;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 25px 0;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }}
        th, td {{
            padding: 14px 16px;
            text-align: left;
            border-bottom: 1px solid #e8ecf1;
        }}
        th {{
            background: linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%);
            color: white;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
            box-shadow: 0 2px 4px rgba(15, 32, 39, 0.2);
        }}
        tr:hover {{
            background: #f8f9fa;
            transition: background 0.2s;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 25px;
            margin: 30px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%);
            color: white;
            padding: 30px 20px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(15, 32, 39, 0.25);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }}
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
            transition: left 0.5s;
        }}
        .stat-card:hover::before {{
            left: 100%;
        }}
        .stat-card:hover {{
            transform: translateY(-5px) scale(1.02);
            box-shadow: 0 8px 30px rgba(15, 32, 39, 0.35);
        }}
        .stat-card h3 {{
            font-size: 3em;
            margin: 0;
            color: white;
            font-weight: 700;
        }}
        .stat-card p {{
            margin: 12px 0 0 0;
            opacity: 0.95;
            font-size: 0.95em;
            font-weight: 500;
        }}
        .finding-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 3px 12px rgba(0,0,0,0.08);
            border-top: 5px solid;
            margin: 20px 0;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .finding-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 18px rgba(0,0,0,0.12);
        }}
        .finding-card.critical {{ 
            border-color: #dc2626;
            background: linear-gradient(135deg, #ffffff 0%, #fff1f2 100%);
        }}
        .finding-card.high {{ 
            border-color: #f59e0b;
            background: linear-gradient(135deg, #ffffff 0%, #fffbeb 100%);
        }}
        .finding-card.medium {{ 
            border-color: #3b82f6;
            background: linear-gradient(135deg, #ffffff 0%, #eff6ff 100%);
        }}
        .finding-card.low {{ 
            border-color: #10b981;
            background: linear-gradient(135deg, #ffffff 0%, #f0fdf4 100%);
        }}
        .finding-card h4 {{
            margin-top: 0;
            color: #2c3e50;
            font-size: 1.3em;
        }}
        .risk-badge {{
            display: inline-block;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            margin: 5px 3px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .risk-critical {{ 
            background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
            color: white;
            box-shadow: 0 2px 6px rgba(220, 38, 38, 0.3);
        }}
        .risk-high {{ 
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
            color: white;
            box-shadow: 0 2px 6px rgba(245, 158, 11, 0.3);
        }}
        .risk-medium {{ 
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            color: white;
            box-shadow: 0 2px 6px rgba(59, 130, 246, 0.3);
        }}
        .risk-low {{ 
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            box-shadow: 0 2px 6px rgba(16, 185, 129, 0.3);
        }}
        code {{
            background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
            padding: 4px 10px;
            border-radius: 6px;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            color: #dc2626;
            font-size: 0.9em;
            border: 1px solid #e2e8f0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        pre {{
            background: linear-gradient(135deg, #0f2027 0%, #1a2332 100%);
            color: #e2e8f0;
            padding: 25px;
            border-radius: 10px;
            overflow-x: auto;
            margin: 20px 0;
            box-shadow: 0 4px 16px rgba(15, 32, 39, 0.2);
            border-left: 4px solid #3b82f6;
        }}
        pre code {{
            background: none;
            color: inherit;
            padding: 0;
            border: none;
        }}
        .permission-item {{
            background: white;
            padding: 12px 15px;
            margin: 8px 0;
            border-radius: 6px;
            border-left: 4px solid;
            box-shadow: 0 1px 4px rgba(0,0,0,0.05);
        }}
        .permission-item.granted {{ 
            border-color: #10b981;
            background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
            box-shadow: 0 1px 4px rgba(16, 185, 129, 0.1);
        }}
        .permission-item.denied {{ 
            border-color: #dc2626;
            background: linear-gradient(135deg, #fff1f2 0%, #ffe4e6 100%);
            box-shadow: 0 1px 4px rgba(220, 38, 38, 0.1);
        }}
        .permission-item.warning {{ 
            border-color: #f59e0b;
            background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%);
            box-shadow: 0 1px 4px rgba(245, 158, 11, 0.1);
        }}
        .summary-box {{
            background: linear-gradient(135deg, #f8f9fa 0%, #ffffff 100%);
            padding: 30px;
            border-radius: 10px;
            margin: 25px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            border: 1px solid #e8ecf1;
        }}
        .summary-box h3 {{
            margin-top: 0;
            color: #1e3c72;
        }}
        .recommendations {{
            background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 50%, #fde68a 100%);
            border: 2px solid #f59e0b;
            padding: 25px;
            border-radius: 10px;
            margin: 25px 0;
            box-shadow: 0 4px 16px rgba(245, 158, 11, 0.2);
        }}
        .recommendations h3 {{
            color: #78350f;
            margin-top: 0;
            font-weight: 700;
        }}
        .recommendations ul {{
            margin-left: 25px;
        }}
        .recommendations li {{
            margin: 12px 0;
            line-height: 1.8;
        }}
        footer {{
            background: linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%);
            color: white;
            padding: 40px;
            text-align: center;
            box-shadow: 0 -4px 20px rgba(15, 32, 39, 0.2);
        }}
        footer p {{
            margin: 8px 0;
        }}
        footer .author {{
            font-weight: 600;
            color: #ecf0f1;
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid rgba(255,255,255,0.1);
        }}
        .toc {{
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 40px;
            border-left: 5px solid #0f2027;
            box-shadow: 0 4px 16px rgba(15, 32, 39, 0.08);
        }}
        .toc h2 {{
            color: #0f2027;
            margin-bottom: 20px;
            font-size: 1.8em;
            font-weight: 700;
        }}
        .toc ul {{
            list-style: none;
            padding-left: 0;
        }}
        .toc li {{
            margin: 10px 0;
        }}
        .toc a {{
            color: #2c3e50;
            text-decoration: none;
            padding: 10px 15px;
            display: block;
            border-radius: 6px;
            transition: all 0.2s;
            border-left: 3px solid transparent;
        }}
        .toc a:hover {{
            background: linear-gradient(135deg, #f1f5f9 0%, #e2e8f0 100%);
            color: #0f2027;
            border-left-color: #0f2027;
            padding-left: 20px;
            box-shadow: 0 2px 8px rgba(15, 32, 39, 0.1);
        }}
        ul, ol {{
            margin-left: 25px;
            margin-top: 10px;
        }}
        li {{
            margin: 8px 0;
            line-height: 1.7;
        }}
        .findings-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 25px;
            margin: 25px 0;
        }}
        @media print {{
            body {{ background: white; padding: 0; }}
            .container {{ box-shadow: none; }}
            section {{ page-break-inside: avoid; }}
            .fixed-header, .back-to-top, .toc-toggle {{ display: none; }}
        }}
        .toc-sidebar {{
            position: fixed;
            left: 0;
            top: 80px;
            width: 280px;
            max-height: calc(100vh - 80px);
            overflow-y: auto;
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
            padding: 20px;
            border-right: 2px solid #e2e8f0;
            box-shadow: 2px 0 10px rgba(0,0,0,0.05);
            z-index: 999;
            transition: transform 0.3s ease;
        }}
        .toc-sidebar.collapsed {{
            transform: translateX(-100%);
        }}
        .toc-toggle {{
            position: fixed;
            left: 0;
            top: 100px;
            z-index: 1000;
            background: #0f2027;
            color: white;
            border: none;
            padding: 10px 15px;
            cursor: pointer;
            border-radius: 0 5px 5px 0;
            box-shadow: 2px 2px 8px rgba(0,0,0,0.2);
            transition: left 0.3s ease;
        }}
        .toc-toggle.sidebar-open {{
            left: 280px;
        }}
        .toc-sidebar h3 {{
            color: #0f2027;
            margin-bottom: 15px;
            font-size: 1.2em;
            font-weight: 700;
            padding-bottom: 10px;
            border-bottom: 2px solid #e2e8f0;
        }}
        .toc-sidebar ul {{
            list-style: none;
            padding-left: 0;
            margin: 0;
        }}
        .toc-sidebar li {{
            margin: 5px 0;
        }}
        .toc-sidebar a {{
            color: #2c3e50;
            text-decoration: none;
            padding: 8px 12px;
            display: block;
            border-radius: 5px;
            font-size: 0.9em;
            transition: all 0.2s;
            border-left: 3px solid transparent;
        }}
        .toc-sidebar a:hover {{
            background: linear-gradient(135deg, #f1f5f9 0%, #e2e8f0 100%);
            color: #0f2027;
            border-left-color: #0f2027;
            padding-left: 15px;
        }}
        .toc-sidebar a.active {{
            background: linear-gradient(135deg, #0f2027 0%, #203a43 100%);
            color: white;
            border-left-color: #2c5364;
        }}
        .back-to-top {{
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%);
            color: white;
            border: none;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(15, 32, 39, 0.3);
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s ease;
            z-index: 1000;
            font-size: 1.2em;
        }}
        .back-to-top.visible {{
            opacity: 1;
            visibility: visible;
        }}
        .back-to-top:hover {{
            transform: translateY(-5px);
            box-shadow: 0 6px 20px rgba(15, 32, 39, 0.4);
        }}
        .section-toggle {{
            background: none;
            border: none;
            color: #0f2027;
            cursor: pointer;
            font-size: 1.5em;
            padding: 0 10px;
            transition: transform 0.3s ease;
        }}
        .section-toggle:hover {{
            transform: scale(1.2);
        }}
        .section-toggle.collapsed {{
            transform: rotate(-90deg);
        }}
        .section-content {{
            transition: max-height 0.3s ease, opacity 0.3s ease;
            overflow: hidden;
        }}
        .section-content.collapsed {{
            max-height: 0;
            opacity: 0;
            padding: 0;
        }}
        section h2 {{
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .copy-btn {{
            background: linear-gradient(135deg, #0f2027 0%, #203a43 100%);
            color: white;
            border: none;
            padding: 5px 12px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.8em;
            margin-left: 10px;
            transition: all 0.2s;
        }}
        .copy-btn:hover {{
            transform: scale(1.05);
            box-shadow: 0 2px 8px rgba(15, 32, 39, 0.3);
        }}
        .copy-btn.copied {{
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        }}
        pre {{
            position: relative;
        }}
        pre .copy-btn {{
            position: absolute;
            top: 10px;
            right: 10px;
        }}
        .sortable th {{
            cursor: pointer;
            user-select: none;
            position: relative;
            padding-right: 30px;
        }}
        .sortable th:hover {{
            background: linear-gradient(135deg, #203a43 0%, #2c5364 50%, #203a43 100%);
        }}
        .sortable th::after {{
            content: '⇅';
            position: absolute;
            right: 10px;
            opacity: 0.5;
            font-size: 0.8em;
        }}
        .sortable th.sort-asc::after {{
            content: '↑';
            opacity: 1;
        }}
        .sortable th.sort-desc::after {{
            content: '↓';
            opacity: 1;
        }}
        .progress-bar {{
            width: 100%;
            height: 25px;
            background: #e2e8f0;
            border-radius: 12px;
            overflow: hidden;
            margin: 10px 0;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #0f2027 0%, #203a43 50%, #2c5364 100%);
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 0.85em;
            font-weight: 600;
            text-shadow: 0 1px 2px rgba(0,0,0,0.2);
        }}
        .dark-mode {{
            background: #1a1a1a;
            color: #e0e0e0;
        }}
        .dark-mode .container {{
            background: #2d2d2d;
        }}
        .dark-mode section {{
            background: linear-gradient(135deg, #2d2d2d 0%, #252525 100%);
            border-left-color: #4a9eff;
        }}
        .dark-mode .stat-card {{
            background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
        }}
        .dark-mode-toggle {{
            background: #2c5f7c;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9em;
        }}
        .dark-mode-toggle:hover {{
            background: #1e4a5f;
        }}
        mark {{
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            color: #78350f;
            padding: 2px 4px;
            border-radius: 3px;
            font-weight: 600;
        }}
        @media (max-width: 768px) {{
            .toc-sidebar {{
                width: 100%;
                max-width: 280px;
            }}
            .content {{
                padding: 30px 20px;
            }}
            section {{
                padding: 20px;
            }}
            .stats {{
                grid-template-columns: 1fr;
            }}
            .fixed-header {{
                flex-wrap: wrap;
            }}
            .fixed-header input, .fixed-header select, .fixed-header button {{
                width: 100%;
                margin: 5px 0;
            }}
            div[style*="margin-left: 280px"] {{
                margin-left: 0 !important;
            }}
        }}
        </style>
        <script>
        // Search and filter functionality
        function searchReports() {{
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const sections = document.querySelectorAll('section');
            
            sections.forEach(section => {{
                const text = section.textContent.toLowerCase();
                if (text.includes(searchTerm) || searchTerm === '') {{
                    section.style.display = 'block';
                }} else {{
                    section.style.display = 'none';
                }}
            }});
            
            // Highlight search term
            if (searchTerm) {{
                highlightText(searchTerm);
            }} else {{
                removeHighlights();
            }}
        }}
        
        function highlightText(term) {{
            removeHighlights();
            const walker = document.createTreeWalker(
                document.body,
                NodeFilter.SHOW_TEXT,
                null,
                false
            );
            
            const textNodes = [];
            let node;
            while (node = walker.nextNode()) {{
                if (node.parentElement && 
                    node.parentElement.tagName !== 'SCRIPT' && 
                    node.parentElement.tagName !== 'STYLE' &&
                    node.parentElement.tagName !== 'INPUT' &&
                    node.parentElement.tagName !== 'SELECT' &&
                    node.parentElement.tagName !== 'BUTTON') {{
                    textNodes.push(node);
                }}
            }}
            
            textNodes.forEach(textNode => {{
                const text = textNode.textContent;
                const escapedTerm = term.replace(/[.*+?^${{}}()|[\\]\\\\]/g, '\\\\$&');
                const regex = new RegExp('(' + escapedTerm + ')', 'gi');
                if (regex.test(text)) {{
                    const highlightedText = text.replace(regex, '<mark>$1</mark>');
                    const wrapper = document.createElement('span');
                    wrapper.innerHTML = highlightedText;
                    textNode.parentNode.replaceChild(wrapper, textNode);
                }}
            }});
        }}
        
        function removeHighlights() {{
            const marks = document.querySelectorAll('mark');
            marks.forEach(mark => {{
                const parent = mark.parentNode;
                if (parent) {{
                    parent.replaceChild(document.createTextNode(mark.textContent), mark);
                    parent.normalize();
                }}
            }});
        }}
        
        function filterByRisk(riskLevel) {{
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {{
                if (riskLevel === 'all') {{
                    alert.style.display = 'block';
                }} else {{
                    const hasRisk = alert.classList.contains('alert-' + riskLevel);
                    alert.style.display = hasRisk ? 'block' : 'none';
                }}
            }});
        }}
        
        function exportToJSON() {{
            const data = {{
                "report_generated": new Date().toISOString(),
                "author": "RFS",
                "content": document.body.innerHTML
            }};
            const blobOptions = {{'type': 'application/json'}};
            const blob = new Blob([JSON.stringify(data, null, 2)], blobOptions);
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'security_report.json';
            a.click();
            URL.revokeObjectURL(url);
        }}
        
        window.printReport = function() {{
            window.print();
        }};
        
        // Table of Contents
        function generateTOC() {{
            const sections = document.querySelectorAll('section[id]');
            const toc = document.getElementById('toc-list');
            if (!toc) return;
            
            sections.forEach(section => {{
                const id = section.id;
                const h2 = section.querySelector('h2');
                if (h2) {{
                    const text = h2.textContent.trim();
                    const li = document.createElement('li');
                    const a = document.createElement('a');
                    a.href = '#' + id;
                    a.textContent = text;
                    a.addEventListener('click', function(e) {{
                        e.preventDefault();
                        section.scrollIntoView({{{{ behavior: 'smooth', block: 'start' }}}});
                        updateActiveTOCLink(id);
                    }});
                    li.appendChild(a);
                    toc.appendChild(li);
                }}
            }});
        }}
        
        function updateActiveTOCLink(activeId) {{
            document.querySelectorAll('.toc-sidebar a').forEach(link => {{
                link.classList.remove('active');
                if (link.getAttribute('href') === '#' + activeId) {{
                    link.classList.add('active');
                }}
            }});
        }}
        
        // Scroll spy for TOC
        function initScrollSpy() {{
            const sections = document.querySelectorAll('section[id]');
            const observer = new IntersectionObserver((entries) => {{
                entries.forEach(entry => {{
                    if (entry.isIntersecting) {{
                        updateActiveTOCLink(entry.target.id);
                    }}
                }});
            }}, {{ rootMargin: '-100px 0px -66%' }});
            
            sections.forEach(section => observer.observe(section));
        }}
        
        // Toggle sidebar
        window.toggleSidebar = function() {{
            const sidebar = document.getElementById('toc-sidebar');
            const toggle = document.getElementById('toc-toggle');
            if (sidebar && toggle) {{
                sidebar.classList.toggle('collapsed');
                toggle.classList.toggle('sidebar-open');
            }}
        }};
        
        // Back to top
        function initBackToTop() {{
            const btn = document.getElementById('back-to-top');
            if (!btn) return;
            
            window.addEventListener('scroll', () => {{
                if (window.pageYOffset > 300) {{
                    btn.classList.add('visible');
                }} else {{
                    btn.classList.remove('visible');
                }}
            }});
            
            btn.addEventListener('click', () => {{
                window.scrollTo({{{{ top: 0, behavior: 'smooth' }}}});
            }});
        }}
        
        // Collapsible sections
        function initCollapsibleSections() {{
            document.querySelectorAll('.section-toggle').forEach(toggle => {{
                toggle.addEventListener('click', function() {{
                    const section = this.closest('section');
                    const content = section.querySelector('.section-content');
                    if (content) {{
                        content.classList.toggle('collapsed');
                        this.classList.toggle('collapsed');
                    }}
                }});
            }});
        }}
        
        // Copy to clipboard
        function initCopyButtons() {{
            document.querySelectorAll('.copy-btn').forEach(btn => {{
                btn.addEventListener('click', function() {{
                    const code = this.closest('pre') || this.closest('code');
                    const text = code ? code.textContent : '';
                    if (text) {{
                        navigator.clipboard.writeText(text).then(() => {{
                            this.textContent = '✓ Copied';
                            this.classList.add('copied');
                            setTimeout(() => {{
                                this.textContent = 'Copy';
                                this.classList.remove('copied');
                            }}, 2000);
                        }});
                    }}
                }});
            }});
        }}
        
        // Sortable tables
        function initSortableTables() {{
            document.querySelectorAll('.sortable').forEach(table => {{
                const headers = table.querySelectorAll('th');
                headers.forEach((header, index) => {{
                    header.addEventListener('click', () => {{
                        sortTable(table, index);
                    }});
                }});
            }});
        }}
        
        function sortTable(table, columnIndex) {{
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const header = table.querySelectorAll('th')[columnIndex];
            const isAsc = header.classList.contains('sort-asc');
            
            // Reset all headers
            table.querySelectorAll('th').forEach(th => {{
                th.classList.remove('sort-asc', 'sort-desc');
            }});
            
            // Sort rows
            rows.sort((a, b) => {{
                const aText = a.cells[columnIndex].textContent.trim();
                const bText = b.cells[columnIndex].textContent.trim();
                const aNum = parseFloat(aText.replace(/[^0-9.-]/g, ''));
                const bNum = parseFloat(bText.replace(/[^0-9.-]/g, ''));
                
                if (!isNaN(aNum) && !isNaN(bNum)) {{
                    return isAsc ? bNum - aNum : aNum - bNum;
                }}
                return isAsc ? bText.localeCompare(aText) : aText.localeCompare(bText);
            }});
            
            // Update header
            header.classList.add(isAsc ? 'sort-desc' : 'sort-asc');
            
            // Reorder rows
            rows.forEach(row => tbody.appendChild(row));
        }}
        
        // Dark mode
        window.toggleDarkMode = function() {{
            document.body.classList.toggle('dark-mode');
            const isDark = document.body.classList.contains('dark-mode');
            localStorage.setItem('darkMode', isDark);
        }};
        
        function initDarkMode() {{
            const saved = localStorage.getItem('darkMode');
            if (saved === 'true') {{
                document.body.classList.add('dark-mode');
            }}
        }}
        
        // Initialize charts
        function initCharts() {{
            if (typeof chartData === 'undefined' || !chartData || !chartData.overall_risk) return;
            
            const overallRisk = chartData.overall_risk;
            const permAssessment = chartData.permissions_assessment || {{}};
            
            // Risk Distribution Chart
            const riskCtx = document.getElementById('riskDistributionChart');
            if (riskCtx && typeof Chart !== 'undefined') {{
                const riskData = {{
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{{
                        label: 'Findings by Risk Level',
                        data: [
                            overallRisk.critical_findings || 0,
                            overallRisk.high_findings || 0,
                            permAssessment.medium_count || 0,
                            permAssessment.low_count || 0
                        ],
                        backgroundColor: [
                            'rgba(220, 38, 38, 0.8)',
                            'rgba(245, 158, 11, 0.8)',
                            'rgba(59, 130, 246, 0.8)',
                            'rgba(16, 185, 129, 0.8)'
                        ],
                        borderColor: [
                            'rgb(220, 38, 38)',
                            'rgb(245, 158, 11)',
                            'rgb(59, 130, 246)',
                            'rgb(16, 185, 129)'
                        ],
                        borderWidth: 2
                    }}]
                }};
                
                new Chart(riskCtx, {{
                    type: 'doughnut',
                    data: riskData,
                    options: {{
                        responsive: true,
                        plugins: {{
                            legend: {{
                                position: 'bottom'
                            }},
                            title: {{
                                display: true,
                                text: 'Risk Level Distribution'
                            }}
                        }}
                    }}
                }});
            }}
            
            // Permission Risk Chart
            const permCtx = document.getElementById('permissionRiskChart');
            if (permCtx && typeof Chart !== 'undefined' && permAssessment.top_risks) {{
                const topRisks = permAssessment.top_risks.slice(0, 10);
                const permLabels = topRisks.map(r => r.permission || r.resource_type || 'Unknown');
                const permScores = topRisks.map(r => r.risk_score || 0);
                
                new Chart(permCtx, {{
                    type: 'bar',
                    data: {{
                        labels: permLabels,
                        datasets: [{{
                            label: 'Risk Score',
                            data: permScores,
                            backgroundColor: 'rgba(15, 32, 39, 0.8)',
                            borderColor: 'rgba(15, 32, 39, 1)',
                            borderWidth: 1
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        indexAxis: 'y',
                        plugins: {{
                            legend: {{
                                display: false
                            }},
                            title: {{
                                display: true,
                                text: 'Top 10 Risk Items'
                            }}
                        }},
                        scales: {{
                            x: {{
                                beginAtZero: true,
                                max: 150
                            }}
                        }}
                    }}
                }});
            }}
            
            // Permissions Distribution Chart
            const permDistCtx = document.getElementById('permissionsDistributionChart');
            if (permDistCtx && typeof Chart !== 'undefined') {{
                const execSummary = document.getElementById('executive-summary');
                if (execSummary) {{
                    const statCards = execSummary.querySelectorAll('.stat-card');
                    if (statCards.length >= 2) {{
                        const granted = parseInt(statCards[1]?.querySelector('h3')?.textContent || '0');
                        const total = parseInt(statCards[0]?.querySelector('h3')?.textContent || '0');
                        const denied = Math.max(0, total - granted);
                        
                        if (total > 0) {{
                            new Chart(permDistCtx, {{
                                type: 'pie',
                                data: {{
                                    labels: ['Granted', 'Denied'],
                                    datasets: [{{
                                        data: [granted, denied],
                                        backgroundColor: [
                                            'rgba(220, 38, 38, 0.8)',
                                            'rgba(16, 185, 129, 0.8)'
                                        ],
                                        borderColor: [
                                            'rgb(220, 38, 38)',
                                            'rgb(16, 185, 129)'
                                        ],
                                        borderWidth: 2
                                    }}]
                                }},
                                options: {{
                                    responsive: true,
                                    plugins: {{
                                        legend: {{
                                            position: 'bottom'
                                        }},
                                        title: {{
                                            display: true,
                                            text: 'Permissions Status Distribution'
                                        }}
                                    }}
                                }}
                            }});
                        }}
                    }}
                }}
            }}
            
            // Resource Access Chart
            const resourceCtx = document.getElementById('resourceAccessChart');
            if (resourceCtx && typeof Chart !== 'undefined') {{
                const execSummary = document.getElementById('executive-summary');
                if (execSummary) {{
                    const statCards = execSummary.querySelectorAll('.stat-card');
                    if (statCards.length >= 7) {{
                        const repos = parseInt(statCards[3]?.querySelector('h3')?.textContent || '0');
                        const secrets = parseInt(statCards[4]?.querySelector('h3')?.textContent || '0');
                        const webhooks = parseInt(statCards[5]?.querySelector('h3')?.textContent || '0');
                        const runners = parseInt(statCards[6]?.querySelector('h3')?.textContent || '0');
                        
                        if (repos > 0 || secrets > 0 || webhooks > 0 || runners > 0) {{
                            new Chart(resourceCtx, {{
                                type: 'bar',
                                data: {{
                                    labels: ['Repositories', 'Secrets', 'Webhooks', 'Runners'],
                                    datasets: [{{
                                        label: 'Count',
                                        data: [repos, secrets, webhooks, runners],
                                        backgroundColor: [
                                            'rgba(15, 32, 39, 0.8)',
                                            'rgba(220, 38, 38, 0.8)',
                                            'rgba(245, 158, 11, 0.8)',
                                            'rgba(59, 130, 246, 0.8)'
                                        ],
                                        borderColor: [
                                            'rgba(15, 32, 39, 1)',
                                            'rgba(220, 38, 38, 1)',
                                            'rgba(245, 158, 11, 1)',
                                            'rgba(59, 130, 246, 1)'
                                        ],
                                        borderWidth: 1
                                    }}]
                                }},
                                options: {{
                                    responsive: true,
                                    plugins: {{
                                        legend: {{
                                            display: false
                                        }},
                                        title: {{
                                            display: true,
                                            text: 'Resource Access Overview'
                                        }}
                                    }},
                                    scales: {{
                                        y: {{
                                            beginAtZero: true
                                        }}
                                    }}
                                }}
                            }});
                        }}
                    }}
                }}
            }}
            
            // Audit Log Timeline Chart
            const auditTimelineCtx = document.getElementById('auditLogTimelineChart');
            if (auditTimelineCtx && typeof Chart !== 'undefined') {{
                const auditSection = document.getElementById('enterprise-audit-log');
                if (auditSection) {{
                    const eventTable = auditSection.querySelector('table tbody');
                    if (eventTable) {{
                        const rows = eventTable.querySelectorAll('tr');
                        const timelineMap = {{}};
                        rows.forEach(row => {{
                            const cells = row.querySelectorAll('td');
                            if (cells.length >= 2) {{
                                const eventType = cells[0]?.textContent?.trim() || '';
                                const count = parseInt(cells[1]?.textContent?.trim() || '0');
                                if (eventType && count > 0) {{
                                    // Use event type as key for now, could be enhanced with actual dates
                                    timelineMap[eventType] = (timelineMap[eventType] || 0) + count;
                                }}
                            }}
                        }});
                        
                        const sortedKeys = Object.keys(timelineMap).sort((a, b) => timelineMap[b] - timelineMap[a]).slice(0, 20);
                        if (sortedKeys.length > 0) {{
                            new Chart(auditTimelineCtx, {{
                                type: 'line',
                                data: {{
                                    labels: sortedKeys,
                                    datasets: [{{
                                        label: 'Event Count',
                                        data: sortedKeys.map(k => timelineMap[k]),
                                        borderColor: 'rgba(15, 32, 39, 1)',
                                        backgroundColor: 'rgba(15, 32, 39, 0.1)',
                                        borderWidth: 2,
                                        fill: true,
                                        tension: 0.4
                                    }}]
                                }},
                                options: {{
                                    responsive: true,
                                    plugins: {{
                                        legend: {{
                                            display: true
                                        }},
                                        title: {{
                                            display: true,
                                            text: 'Audit Log Event Activity'
                                        }}
                                    }},
                                    scales: {{
                                        y: {{
                                            beginAtZero: true
                                        }},
                                        x: {{
                                            ticks: {{
                                                maxRotation: 45,
                                                minRotation: 45
                                            }}
                                        }}
                                    }}
                                }}
                            }});
                        }}
                    }}
                }}
            }}
            
            // Audit Log Event Types Chart
            const auditEventTypesCtx = document.getElementById('auditLogEventTypesChart');
            if (auditEventTypesCtx && typeof Chart !== 'undefined') {{
                const auditSection = document.getElementById('enterprise-audit-log');
                if (auditSection) {{
                    const eventTable = auditSection.querySelector('table tbody');
                    if (eventTable) {{
                        const rows = eventTable.querySelectorAll('tr');
                        const labels = [];
                        const data = [];
                        
                        rows.forEach(row => {{
                            const cells = row.querySelectorAll('td');
                            if (cells.length >= 2) {{
                                labels.push(cells[0]?.textContent?.trim() || '');
                                data.push(parseInt(cells[1]?.textContent?.trim() || '0'));
                            }}
                        }});
                        
                        if (labels.length > 0 && data.length > 0) {{
                            new Chart(auditEventTypesCtx, {{
                                type: 'pie',
                                data: {{
                                    labels: labels.slice(0, 10),
                                    datasets: [{{
                                        data: data.slice(0, 10),
                                        backgroundColor: [
                                            'rgba(220, 38, 38, 0.8)',
                                            'rgba(245, 158, 11, 0.8)',
                                            'rgba(59, 130, 246, 0.8)',
                                            'rgba(16, 185, 129, 0.8)',
                                            'rgba(139, 92, 246, 0.8)',
                                            'rgba(236, 72, 153, 0.8)',
                                            'rgba(14, 165, 233, 0.8)',
                                            'rgba(34, 197, 94, 0.8)',
                                            'rgba(251, 146, 60, 0.8)',
                                            'rgba(168, 85, 247, 0.8)'
                                        ],
                                        borderWidth: 2
                                    }}]
                                }},
                                options: {{
                                    responsive: true,
                                    plugins: {{
                                        legend: {{
                                            position: 'right'
                                        }},
                                        title: {{
                                            display: true,
                                            text: 'Event Types Distribution'
                                        }}
                                    }}
                                }}
                            }});
                        }}
                    }}
                }}
            }}
            
            // Security Alerts Chart
            const securityAlertsCtx = document.getElementById('securityAlertsChart');
            if (securityAlertsCtx && typeof Chart !== 'undefined') {{
                const securitySection = document.getElementById('security-analysis');
                if (securitySection) {{
                    const statCards = securitySection.querySelectorAll('.stat-card');
                    if (statCards.length >= 4) {{
                        const codeAlerts = parseInt(statCards[1]?.querySelector('h3')?.textContent || '0');
                        const secretAlerts = parseInt(statCards[2]?.querySelector('h3')?.textContent || '0');
                        const dependabot = parseInt(statCards[3]?.querySelector('h3')?.textContent || '0');
                        
                        if (codeAlerts > 0 || secretAlerts > 0 || dependabot > 0) {{
                            new Chart(securityAlertsCtx, {{
                                type: 'bar',
                                data: {{
                                    labels: ['Code Alerts', 'Secret Alerts', 'Dependabot'],
                                    datasets: [{{
                                        label: 'Alert Count',
                                        data: [codeAlerts, secretAlerts, dependabot],
                                        backgroundColor: [
                                            'rgba(220, 38, 38, 0.8)',
                                            'rgba(245, 158, 11, 0.8)',
                                            'rgba(59, 130, 246, 0.8)'
                                        ],
                                        borderColor: [
                                            'rgba(220, 38, 38, 1)',
                                            'rgba(245, 158, 11, 1)',
                                            'rgba(59, 130, 246, 1)'
                                        ],
                                        borderWidth: 1
                                    }}]
                                }},
                                options: {{
                                    responsive: true,
                                    plugins: {{
                                        legend: {{
                                            display: false
                                        }},
                                        title: {{
                                            display: true,
                                            text: 'Security Alerts Distribution'
                                        }}
                                    }},
                                    scales: {{
                                        y: {{
                                            beginAtZero: true
                                        }}
                                    }}
                                }}
                            }});
                        }}
                    }}
                }}
            }}
            
            // Repository Security Chart
            const repoSecurityCtx = document.getElementById('repositorySecurityChart');
            if (repoSecurityCtx && typeof Chart !== 'undefined') {{
                const securitySection = document.getElementById('security-analysis');
                if (securitySection) {{
                    const statCards = securitySection.querySelectorAll('.stat-card');
                    if (statCards.length >= 6) {{
                        const reposAnalyzed = parseInt(statCards[0]?.querySelector('h3')?.textContent || '0');
                        const reposWithVulns = parseInt(statCards[4]?.querySelector('h3')?.textContent || '0');
                        const reposWithProtection = parseInt(statCards[5]?.querySelector('h3')?.textContent || '0');
                        const reposWithoutProtection = reposAnalyzed - reposWithProtection;
                        
                        if (reposAnalyzed > 0) {{
                            new Chart(repoSecurityCtx, {{
                                type: 'doughnut',
                                data: {{
                                    labels: ['With Protection', 'Without Protection', 'With Vulnerabilities'],
                                    datasets: [{{
                                        data: [reposWithProtection, reposWithoutProtection, reposWithVulns],
                                        backgroundColor: [
                                            'rgba(16, 185, 129, 0.8)',
                                            'rgba(245, 158, 11, 0.8)',
                                            'rgba(220, 38, 38, 0.8)'
                                        ],
                                        borderWidth: 2
                                    }}]
                                }},
                                options: {{
                                    responsive: true,
                                    plugins: {{
                                        legend: {{
                                            position: 'bottom'
                                        }},
                                        title: {{
                                            display: true,
                                            text: 'Repository Security Status'
                                        }}
                                    }}
                                }}
                            }});
                        }}
                    }}
                }}
            }}
            
            // Runner Status Chart
            const runnerStatusCtx = document.getElementById('runnerStatusChart');
            if (runnerStatusCtx && typeof Chart !== 'undefined') {{
                const runnerSection = document.getElementById('runner-analysis');
                if (runnerSection) {{
                    const statCards = runnerSection.querySelectorAll('.stat-card');
                    if (statCards.length >= 3) {{
                        const total = parseInt(statCards[0]?.querySelector('h3')?.textContent || '0');
                        const online = parseInt(statCards[1]?.querySelector('h3')?.textContent || '0');
                        const offline = parseInt(statCards[2]?.querySelector('h3')?.textContent || '0');
                        
                        if (total > 0) {{
                            new Chart(runnerStatusCtx, {{
                                type: 'pie',
                                data: {{
                                    labels: ['Online', 'Offline'],
                                    datasets: [{{
                                        data: [online, offline],
                                        backgroundColor: [
                                            'rgba(16, 185, 129, 0.8)',
                                            'rgba(156, 163, 175, 0.8)'
                                        ],
                                        borderWidth: 2
                                    }}]
                                }},
                                options: {{
                                    responsive: true,
                                    plugins: {{
                                        legend: {{
                                            position: 'bottom'
                                        }},
                                        title: {{
                                            display: true,
                                            text: 'Runner Status Distribution'
                                        }}
                                    }}
                                }}
                            }});
                        }}
                    }}
                }}
            }}
            
            // Runner OS Chart
            const runnerOSCtx = document.getElementById('runnerOSChart');
            if (runnerOSCtx && typeof Chart !== 'undefined') {{
                const runnerSection = document.getElementById('runner-analysis');
                if (runnerSection) {{
                    const osList = runnerSection.querySelector('ul');
                    if (osList) {{
                        const osItems = osList.querySelectorAll('li');
                        const osData = {{}};
                        osItems.forEach(item => {{
                            const text = item.textContent || '';
                            const match = text.match(/(\\w+):\\s*(\\d+)/);
                            if (match) {{
                                osData[match[1]] = parseInt(match[2]);
                            }}
                        }});
                        
                        const osLabels = Object.keys(osData);
                        const osCounts = Object.values(osData);
                        
                        if (osLabels.length > 0) {{
                            new Chart(runnerOSCtx, {{
                                type: 'bar',
                                data: {{
                                    labels: osLabels,
                                    datasets: [{{
                                        label: 'Runners',
                                        data: osCounts,
                                        backgroundColor: 'rgba(15, 32, 39, 0.8)',
                                        borderColor: 'rgba(15, 32, 39, 1)',
                                        borderWidth: 1
                                    }}]
                                }},
                                options: {{
                                    responsive: true,
                                    plugins: {{
                                        legend: {{
                                            display: false
                                        }},
                                        title: {{
                                            display: true,
                                            text: 'OS Distribution'
                                        }}
                                    }},
                                    scales: {{
                                        y: {{
                                            beginAtZero: true
                                        }}
                                    }}
                                }}
                            }});
                        }}
                    }}
                }}
            }}
            
            // Network Exposure Chart
            const networkExposureCtx = document.getElementById('networkExposureChart');
            if (networkExposureCtx && typeof Chart !== 'undefined') {{
                const runnerSection = document.getElementById('runner-analysis');
                if (runnerSection) {{
                    const statCards = runnerSection.querySelectorAll('.stat-card');
                    if (statCards.length >= 6) {{
                        const totalIPs = parseInt(statCards[3]?.querySelector('h3')?.textContent || '0');
                        const totalHostnames = parseInt(statCards[4]?.querySelector('h3')?.textContent || '0');
                        const onlineExposed = parseInt(statCards[5]?.querySelector('h3')?.textContent || '0');
                        
                        if (totalIPs > 0 || totalHostnames > 0) {{
                            new Chart(networkExposureCtx, {{
                                type: 'bar',
                                data: {{
                                    labels: ['IP Addresses', 'Hostnames', 'Online Exposed'],
                                    datasets: [{{
                                        label: 'Count',
                                        data: [totalIPs, totalHostnames, onlineExposed],
                                        backgroundColor: [
                                            'rgba(220, 38, 38, 0.8)',
                                            'rgba(245, 158, 11, 0.8)',
                                            'rgba(59, 130, 246, 0.8)'
                                        ],
                                        borderWidth: 1
                                    }}]
                                }},
                                options: {{
                                    responsive: true,
                                    plugins: {{
                                        legend: {{
                                            display: false
                                        }},
                                        title: {{
                                            display: true,
                                            text: 'Network Exposure Metrics'
                                        }}
                                    }},
                                    scales: {{
                                        y: {{
                                            beginAtZero: true
                                        }}
                                    }}
                                }}
                            }});
                        }}
                    }}
                }}
            }}
            
            // Repository Traffic Chart
            const trafficCtx = document.getElementById('repositoryTrafficChart');
            if (trafficCtx && typeof Chart !== 'undefined') {{
                const insightsSection = document.getElementById('repository-insights');
                if (insightsSection) {{
                    const statCards = insightsSection.querySelectorAll('.stat-card');
                    if (statCards.length >= 4) {{
                        const clones = parseInt(statCards[1]?.querySelector('h3')?.textContent || '0');
                        const views = parseInt(statCards[2]?.querySelector('h3')?.textContent || '0');
                        const commits = parseInt(statCards[3]?.querySelector('h3')?.textContent || '0');
                        
                        if (clones > 0 || views > 0 || commits > 0) {{
                            new Chart(trafficCtx, {{
                                type: 'line',
                                data: {{
                                    labels: ['Clones', 'Views', 'Commits'],
                                    datasets: [{{
                                        label: 'Activity',
                                        data: [clones, views, commits],
                                        borderColor: 'rgba(15, 32, 39, 1)',
                                        backgroundColor: 'rgba(15, 32, 39, 0.1)',
                                        borderWidth: 2,
                                        fill: true,
                                        tension: 0.4
                                    }}]
                                }},
                                options: {{
                                    responsive: true,
                                    plugins: {{
                                        legend: {{
                                            display: false
                                        }},
                                        title: {{
                                            display: true,
                                            text: 'Repository Traffic Overview'
                                        }}
                                    }},
                                    scales: {{
                                        y: {{
                                            beginAtZero: true,
                                            type: 'logarithmic'
                                        }}
                                    }}
                                }}
                            }});
                        }}
                    }}
                }}
            }}
        }}
        
        // Initialize on load
        document.addEventListener('DOMContentLoaded', function() {{
            generateTOC();
            initScrollSpy();
            initBackToTop();
            initCollapsibleSections();
            initCopyButtons();
            initSortableTables();
            initDarkMode();
            initCharts();
        }});
        </script>
    </head>
    <body>
        <div class="fixed-header" style="position: fixed; top: 0; left: 0; right: 0; background: #1a252f; padding: 15px; z-index: 1000; box-shadow: 0 2px 10px rgba(0,0,0,0.3);">
            <div style="max-width: 1400px; margin: 0 auto; display: flex; gap: 15px; align-items: center; flex-wrap: wrap;">
                <input type="text" id="searchInput" placeholder="Search report..." 
                       onkeyup="searchReports()" 
                       style="flex: 1; min-width: 200px; padding: 10px; border-radius: 5px; border: 1px solid #2c3e50; background: white; color: #2c3e50;">
                <select id="riskFilter" onchange="filterByRisk(this.value)" 
                        style="padding: 10px; border-radius: 5px; border: 1px solid #2c3e50; background: white; color: #2c3e50;">
                    <option value="all">All Risk Levels</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                <button class="dark-mode-toggle" onclick="toggleDarkMode()" title="Toggle Dark Mode">
                    🌓 Dark Mode
                </button>
                <button onclick="exportToJSON()" 
                        style="padding: 10px 20px; border-radius: 5px; border: none; background: #2c5f7c; color: white; cursor: pointer;">
                    Export JSON
                </button>
                <button onclick="window.printReport()" 
                        style="padding: 10px 20px; border-radius: 5px; border: none; background: #2c5f7c; color: white; cursor: pointer;">
                    Print
                </button>
            </div>
        </div>
        <button id="toc-toggle" class="toc-toggle" onclick="toggleSidebar()" title="Toggle Table of Contents">☰</button>
        <div id="toc-sidebar" class="toc-sidebar">
            <h3>📑 Table of Contents</h3>
            <ul id="toc-list"></ul>
        </div>
        <button id="back-to-top" class="back-to-top" title="Back to Top">↑</button>
        <div style="margin-top: 80px; margin-left: 280px;">
    <div class="container">
        <header>
            <h1>🔐 GitHub API Key Security Analysis Report</h1>
            <p class="subtitle">Comprehensive Security Assessment & Findings</p>
            <p class="subtitle" style="margin-top: 10px; font-size: 0.95em; opacity: 0.85;">Generated: {timestamp}</p>
            <p class="author">Author: <strong>RFS</strong></p>
        </header>
        <div class="content">
            {content}
        </div>
        <script>
        const chartData = {chart_data_json};
        </script>
        <footer>
            <p><strong>GitHub API Key Security Analysis Report</strong></p>
            <p>Confidential Security Document - Handle with Appropriate Security Measures</p>
            <p>Generated: {timestamp}</p>
            <p class="author">Report Author: <strong>RFS</strong></p>
            <p style="margin-top: 15px; opacity: 0.8; font-size: 0.9em;">
                ⚠️ This report contains sensitive security information. Do not share publicly or commit to version control.
            </p>
        </footer>
    </div>
    <script>
        const now = new Date();
        const dateStr = now.toLocaleString('en-US', {{
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        }});
        document.querySelectorAll('[id="date"], [id="footer-date"]').forEach(el => {{
            if (el) el.textContent = dateStr;
        }});
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {{
            anchor.addEventListener('click', function (e) {{
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {{
                    target.scrollIntoView({{{{ behavior: 'smooth', block: 'start' }}}});
                }}
            }});
        }});
    </script>
</body>
</html>"""
    
    def generate_report(
        self,
        permissions_data: Optional[Dict[str, Any]] = None,
        enumeration_data: Optional[Dict[str, Any]] = None,
        runner_data: Optional[Dict[str, Any]] = None,
        resources_data: Optional[Dict[str, Any]] = None,
        test_results: Optional[Dict[str, Any]] = None,
        output_file: Optional[str] = None,
        drift_data: Optional[Dict[str, Any]] = None,
        compliance_data: Optional[Dict[str, Any]] = None,
        rate_limit_data: Optional[Dict[str, Any]] = None,
        remediation_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate HTML report from analysis findings.
        
        Args:
            permissions_data: Permission validation results
            enumeration_data: Organization enumeration results
            runner_data: Runner telemetry data
            resources_data: Resource listing results (projects, repos, webhooks, secrets)
            test_results: Test suite results
            output_file: Optional file path to save report
            
        Returns:
            HTML report as string
        """
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Calculate risk scores
        risk_scorer = RiskScorer()
        permissions_assessment = {}
        resources_assessment = {}
        overall_risk = {}
        recommendations = []
        
        if permissions_data:
            permissions_assessment = risk_scorer.assess_permissions(permissions_data)
        
        if resources_data:
            resources_assessment = risk_scorer.assess_resources(resources_data)
        
        if permissions_assessment and resources_assessment:
            overall_risk = risk_scorer.calculate_overall_risk(
                permissions_assessment, resources_assessment
            )
            recommendations = risk_scorer.generate_recommendations(
                overall_risk, permissions_assessment, resources_assessment
            )
        
        content_sections = []
        
        # Risk Assessment Summary (before executive summary)
        if overall_risk:
            content_sections.append(self._generate_risk_assessment_section(
                overall_risk, permissions_assessment, resources_assessment, recommendations
            ))
        
        # Executive Summary
        content_sections.append(self._generate_executive_summary(
            permissions_data, enumeration_data, runner_data, resources_data, overall_risk
        ))
        
        # Permissions Analysis
        if permissions_data:
            content_sections.append(self._generate_permissions_section(permissions_data))
        
        # Accessible Resources
        if resources_data or enumeration_data:
            content_sections.append(self._generate_resources_section(
                resources_data, enumeration_data
            ))
        
        # GitHub Actions Detection
        if resources_data and "actions" in resources_data:
            content_sections.append(self._generate_actions_section(
                resources_data.get("actions", {})
            ))
        
        # All Organizations
        if enumeration_data and "organizations" in enumeration_data:
            content_sections.append(self._generate_organizations_section(
                enumeration_data
            ))
        
        # Security Analysis
        if resources_data and "security" in resources_data:
            content_sections.append(self._generate_security_analysis_section(
                resources_data.get("security", {})
            ))
        
        # Repository Analysis
        if resources_data and "repository_analysis" in resources_data:
            content_sections.append(self._generate_repository_analysis_section(
                resources_data.get("repository_analysis", {})
            ))
        
        # Codespaces Detection
        if resources_data and "codespaces" in resources_data:
            content_sections.append(self._generate_codespaces_section(
                resources_data.get("codespaces", {})
            ))
        
        # Issues and PRs Analysis
        if resources_data and "issues_prs" in resources_data:
            content_sections.append(self._generate_issues_prs_section(
                resources_data.get("issues_prs", {})
            ))
        
        # Content Analysis
        if resources_data and "content_analysis" in resources_data:
            content_sections.append(self._generate_content_analysis_section(
                resources_data.get("content_analysis", {})
            ))
        
        # Packages Analysis
        if resources_data and "packages" in resources_data:
            content_sections.append(self._generate_packages_section(
                resources_data.get("packages", {})
            ))
        
        # Token Metadata
        if resources_data and "token_metadata" in resources_data:
            content_sections.append(self._generate_token_metadata_section(
                resources_data.get("token_metadata", {}),
                resources_data.get("token_usage", {})
            ))
        
        # Repository Insights
        if resources_data and "repository_insights" in resources_data:
            content_sections.append(self._generate_repository_insights_section(
                resources_data.get("repository_insights", {})
            ))
        
        # Enterprise Audit Logs
        if resources_data and "enterprise_audit_log" in resources_data:
            content_sections.append(self._generate_enterprise_audit_log_section(
                resources_data.get("enterprise_audit_log", {})
            ))
        
        # Organization Audit Logs
        if resources_data and "org_audit_logs" in resources_data:
            content_sections.append(self._generate_org_audit_log_section(
                resources_data.get("org_audit_logs", {})
            ))
        
        # Gists Analysis
        if resources_data and "gists" in resources_data:
            content_sections.append(self._generate_gists_section(
                resources_data.get("gists", {}),
                resources_data.get("starred_gists", {})
            ))
        
        # User Activity
        if resources_data and "user_activity" in resources_data:
            content_sections.append(self._generate_user_activity_section(
                resources_data.get("user_activity", {})
            ))
        
        # Discussions
        if resources_data and "discussions" in resources_data:
            content_sections.append(self._generate_discussions_section(
                resources_data.get("discussions", {})
            ))
        
        # Commit Analysis
        if resources_data and "commits" in resources_data:
            content_sections.append(self._generate_commits_section(
                resources_data.get("commits", {})
            ))
        
        # Branch Analysis
        if resources_data and "branches" in resources_data:
            content_sections.append(self._generate_branches_section(
                resources_data.get("branches", {})
            ))
        
        # Team Analysis
        if resources_data and "teams" in resources_data:
            content_sections.append(self._generate_teams_section(
                resources_data.get("teams", {})
            ))
        
        # Notifications Analysis
        if resources_data and "notifications" in resources_data:
            content_sections.append(self._generate_notifications_section(
                resources_data.get("notifications", {})
            ))
        
        # Webhook Detailed Analysis
        if resources_data and "webhooks_detailed" in resources_data:
            content_sections.append(self._generate_webhooks_detailed_section(
                resources_data.get("webhooks_detailed", {})
            ))
        
        # OAuth App Analysis
        if resources_data and "oauth_apps" in resources_data:
            content_sections.append(self._generate_oauth_apps_section(
                resources_data.get("oauth_apps", {}),
                resources_data.get("org_oauth_apps", {})
            ))
        
        # GitHub App Analysis
        if resources_data and "github_apps" in resources_data:
            content_sections.append(self._generate_github_apps_section(
                resources_data.get("github_apps", {}),
                resources_data.get("org_github_apps", {})
            ))
        
        # Dependency Analysis
        if resources_data and "dependencies" in resources_data:
            content_sections.append(self._generate_dependencies_section(
                resources_data.get("dependencies", {})
            ))
        
        # PR Reviews Analysis
        if resources_data and "pr_reviews" in resources_data:
            content_sections.append(self._generate_pr_reviews_section(
                resources_data.get("pr_reviews", {})
            ))
        
        # Repository Settings Analysis
        if resources_data and "repository_settings" in resources_data:
            content_sections.append(self._generate_repository_settings_section(
                resources_data.get("repository_settings", {})
            ))
        
        # Organization Settings Analysis
        if resources_data and "organization_settings" in resources_data:
            content_sections.append(self._generate_organization_settings_section(
                resources_data.get("organization_settings", {})
            ))
        
        # Environment Secrets Analysis
        if resources_data and "environment_secrets" in resources_data:
            content_sections.append(self._generate_environment_secrets_section(
                resources_data.get("environment_secrets", {})
            ))
        
        # Milestones Analysis
        if resources_data and "milestones" in resources_data:
            content_sections.append(self._generate_milestones_section(
                resources_data.get("milestones", {})
            ))
        
        # Labels Analysis
        if resources_data and "labels" in resources_data:
            content_sections.append(self._generate_labels_section(
                resources_data.get("labels", {})
            ))
        
        # Projects Analysis
        if resources_data and "projects_analysis" in resources_data:
            content_sections.append(self._generate_projects_section(
                resources_data.get("projects_analysis", {})
            ))
        
        # Reactions Analysis
        if resources_data and "reactions" in resources_data:
            content_sections.append(self._generate_reactions_section(
                resources_data.get("reactions", {})
            ))
        
        # Commit Comments Analysis
        if resources_data and "commit_comments" in resources_data:
            content_sections.append(self._generate_commit_comments_section(
                resources_data.get("commit_comments", {})
            ))
        
        # PR Files Analysis
        if resources_data and "pr_files" in resources_data:
            content_sections.append(self._generate_pr_files_section(
                resources_data.get("pr_files", {})
            ))
        
        # Issue Events Analysis
        if resources_data and "issue_events" in resources_data:
            content_sections.append(self._generate_issue_events_section(
                resources_data.get("issue_events", {})
            ))
        
        # Contributors Analysis
        if resources_data and "contributors" in resources_data:
            content_sections.append(self._generate_contributors_section(
                resources_data.get("contributors", {})
            ))
        
        # Stargazers/Watchers Analysis
        if resources_data and "stargazers_watchers" in resources_data:
            content_sections.append(self._generate_stargazers_watchers_section(
                resources_data.get("stargazers_watchers", {})
            ))
        
        # Fork Network Analysis
        if resources_data and "fork_network" in resources_data:
            content_sections.append(self._generate_fork_network_section(
                resources_data.get("fork_network", {})
            ))
        
        # Release Assets Analysis
        if resources_data and "release_assets" in resources_data:
            content_sections.append(self._generate_release_assets_section(
                resources_data.get("release_assets", {})
            ))
        
        # Repository Invitations Analysis
        if resources_data and "repository_invitations" in resources_data:
            content_sections.append(self._generate_repository_invitations_section(
                resources_data.get("repository_invitations", {})
            ))
        
        # Repository Transfer Analysis
        if resources_data and "repository_transfers" in resources_data:
            content_sections.append(self._generate_repository_transfers_section(
                resources_data.get("repository_transfers", {})
            ))
        
        # Workflow Run Logs Analysis
        if resources_data and "workflow_run_logs" in resources_data:
            content_sections.append(self._generate_workflow_run_logs_section(
                resources_data.get("workflow_run_logs", {})
            ))
        
        # Artifact Details Analysis
        if resources_data and "artifact_details" in resources_data:
            content_sections.append(self._generate_artifact_details_section(
                resources_data.get("artifact_details", {})
            ))
        
        # Secret Scanning Alerts Analysis
        if resources_data and "secret_scanning_alerts" in resources_data:
            content_sections.append(self._generate_secret_scanning_alerts_section(
                resources_data.get("secret_scanning_alerts", {})
            ))
        
        # Code Scanning Alerts Analysis
        if resources_data and "code_scanning_alerts" in resources_data:
            content_sections.append(self._generate_code_scanning_alerts_section(
                resources_data.get("code_scanning_alerts", {})
            ))
        
        # Repository Topics Analysis
        if resources_data and "repository_topics" in resources_data:
            content_sections.append(self._generate_repository_topics_section(
                resources_data.get("repository_topics", {})
            ))
        
        # Repository Languages Analysis
        if resources_data and "repository_languages" in resources_data:
            content_sections.append(self._generate_repository_languages_section(
                resources_data.get("repository_languages", {})
            ))
        
        # Enterprise Settings Analysis
        if resources_data and "enterprise_settings" in resources_data:
            content_sections.append(self._generate_enterprise_settings_section(
                resources_data.get("enterprise_settings", {})
            ))
        
        # Repository Statistics Analysis
        if resources_data and "repository_statistics" in resources_data:
            content_sections.append(self._generate_repository_statistics_section(
                resources_data.get("repository_statistics", {})
            ))
        
        # Runner Analysis
        if runner_data:
            content_sections.append(self._generate_runner_section(runner_data))
        
        # Security Findings
        content_sections.append(self._generate_security_findings(
            permissions_data, resources_data, runner_data
        ))
        
        # Test Results
        if test_results:
            content_sections.append(self._generate_test_results_section(test_results))
        
        # Permission Drift Detection
        if drift_data:
            content_sections.append(self._generate_drift_detection_section(drift_data))
        
        # Compliance Checking
        if compliance_data:
            content_sections.append(self._generate_compliance_section(compliance_data))
        
        # Rate Limit Monitoring
        if rate_limit_data:
            content_sections.append(self._generate_rate_limit_section(rate_limit_data))
        
        # Automated Remediation Suggestions
        if remediation_data:
            content_sections.append(self._generate_remediation_section(remediation_data))
        
        # Reorder sections - move recommendations to end
        # Find recommendations section index
        rec_index = None
        for i, section in enumerate(content_sections):
            if 'id="recommendations"' in section:
                rec_index = i
                break
        
        # Move recommendations to end if found
        if rec_index is not None:
            rec_section = content_sections.pop(rec_index)
            content_sections.append(rec_section)
        else:
            # Add recommendations if not found
            content_sections.append(self._generate_recommendations(
                permissions_data, resources_data
            ))
        
        content = "\n".join(content_sections)
        
        # Prepare data for JavaScript charts
        chart_data = {
            "overall_risk": overall_risk,
            "permissions_assessment": permissions_assessment,
            "resources_assessment": resources_assessment
        }
        
        # Convert chart data to JSON string for template
        chart_data_json = json.dumps(chart_data)
        
        html = self.template.format(
            timestamp=timestamp,
            content=content,
            chart_data_json=chart_data_json
        )
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html)
        
        return html
    
    def _generate_risk_assessment_section(
        self,
        overall_risk: Dict[str, Any],
        permissions_assessment: Dict[str, Any],
        resources_assessment: Dict[str, Any],
        recommendations: List[Dict[str, Any]]
    ) -> str:
        """Generate risk assessment section."""
        risk_level = overall_risk.get("risk_level", "medium")
        # Handle both string and RiskLevel enum
        if hasattr(risk_level, 'value'):
            risk_level = risk_level.value
        risk_level = str(risk_level).lower() if isinstance(risk_level, str) else "medium"
        risk_score = overall_risk.get("overall_risk_score", 0)
        critical_findings = overall_risk.get("critical_findings", 0)
        high_findings = overall_risk.get("high_findings", 0)
        
        # Risk level styling
        risk_class = f"alert-{risk_level}" if risk_level in ["critical", "high", "medium", "low", "info"] else "alert-medium"
        
        # Top risks
        top_permission_risks = permissions_assessment.get("top_risks", [])[:5]
        top_resource_risks = resources_assessment.get("top_risks", [])[:5]
        
        top_risks_html = ""
        for risk in top_permission_risks + top_resource_risks:
            risk_type = risk.get("permission") or risk.get("resource_type", "Unknown")
            risk_score_val = risk.get("risk_score", 0)
            risk_level_val = risk.get("risk_level", "medium")
            # Handle both string and RiskLevel enum
            if hasattr(risk_level_val, 'value'):
                risk_level_val = risk_level_val.value
            risk_level_str = str(risk_level_val).upper() if isinstance(risk_level_val, str) else str(risk_level_val)
            top_risks_html += f"""
                <tr>
                    <td><code>{risk_type}</code></td>
                    <td><span class="risk-badge risk-{risk_level_val}">{risk_level_str}</span></td>
                    <td>{risk_score_val}</td>
                </tr>
            """
        
        if not top_risks_html:
            top_risks_html = "<tr><td colspan='3'>No risks identified</td></tr>"
        
        # Recommendations
        recommendations_html = ""
        for rec in recommendations[:5]:
            priority = rec.get("priority", "MEDIUM")
            title = rec.get("title", "")
            description = rec.get("description", "")
            actions = rec.get("actions", [])
            
            actions_list = "".join([f"<li>{action}</li>" for action in actions[:3]])
            
            recommendations_html += f"""
                <div class="finding-card {priority.lower()}">
                    <h4>{title} <span class="risk-badge risk-{priority.lower()}">{priority}</span></h4>
                    <p>{description}</p>
                    <ul>{actions_list}</ul>
                </div>
            """
        
        return f"""
        <section id="risk-assessment">
            <h2>
                0. Risk Assessment & Prioritization
                <button class="section-toggle" onclick="this.closest('section').querySelector('.section-content').classList.toggle('collapsed'); this.classList.toggle('collapsed');" title="Collapse/Expand Section">▼</button>
            </h2>
            <div class="section-content">
                <div class="alert {risk_class}">
                    <h3 style="margin-top: 0;">🎯 Overall Risk Score: {risk_score}</h3>
                    <p><strong>Risk Level:</strong> <span class="risk-badge risk-{risk_level}">{risk_level.upper() if isinstance(risk_level, str) else str(risk_level).upper()}</span></p>
                    <p><strong>Critical Findings:</strong> {critical_findings} | <strong>High Findings:</strong> {high_findings}</p>
                    <div class="progress-bar" style="margin-top: 15px;">
                        <div class="progress-fill" style="width: {min(risk_score / 2, 100)}%;">
                            {risk_score} / 200
                        </div>
                    </div>
                </div>
                
                <div class="stats">
                    <div class="stat-card">
                        <h3>{overall_risk.get('permissions_risk', 0)}</h3>
                        <p>Permissions Risk</p>
                    </div>
                    <div class="stat-card">
                        <h3>{overall_risk.get('resources_risk', 0)}</h3>
                        <p>Resources Risk</p>
                    </div>
                    <div class="stat-card">
                        <h3>{critical_findings}</h3>
                        <p>Critical Findings</p>
                    </div>
                    <div class="stat-card">
                        <h3>{high_findings}</h3>
                        <p>High Findings</p>
                    </div>
                </div>
                
                <h3>Top Risks</h3>
                <table class="sortable">
                    <thead>
                        <tr>
                            <th>Risk Item</th>
                            <th>Risk Level</th>
                            <th>Risk Score</th>
                        </tr>
                    </thead>
                    <tbody>
                        {top_risks_html}
                    </tbody>
                </table>
                
                <h3>Risk Distribution</h3>
                <div style="max-width: 600px; margin: 20px 0;">
                    <canvas id="riskDistributionChart"></canvas>
                </div>
                
                <h3>Permission Risk Breakdown</h3>
                <div style="max-width: 600px; margin: 20px 0;">
                    <canvas id="permissionRiskChart"></canvas>
                </div>
                
                <h3>Actionable Recommendations</h3>
                <div class="findings-grid">
                    {recommendations_html}
                </div>
            </div>
        </section>
        """
    
    def _generate_executive_summary(
        self,
        permissions_data: Optional[Dict[str, Any]],
        enumeration_data: Optional[Dict[str, Any]],
        runner_data: Optional[Dict[str, Any]],
        resources_data: Optional[Dict[str, Any]],
        overall_risk: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate executive summary section."""
        total_permissions = 0
        granted_permissions = 0
        critical_granted = 0
        total_repos = 0
        total_secrets = 0
        total_webhooks = 0
        total_runners = 0
        
        if permissions_data:
            summary = permissions_data.get("summary", {})
            total_permissions = summary.get("total_tested", 0)
            granted_permissions = summary.get("granted", 0)
            critical_perms = permissions_data.get("critical_permissions", {})
            critical_granted = sum(1 for p in critical_perms.values() if p.get("granted", False))
        
        if enumeration_data:
            repos = enumeration_data.get("repositories", [])
            total_repos = len(repos) if isinstance(repos, list) else 0
        
        if resources_data:
            if "repositories" in resources_data:
                total_repos = resources_data["repositories"].get("total", 0)
            if "webhooks" in resources_data:
                total_webhooks = resources_data["webhooks"].get("total", 0)
            if "secrets" in resources_data:
                secrets = resources_data.get("secrets", [])
                total_secrets = len(secrets) if isinstance(secrets, list) else 0
        
        if runner_data:
            total_runners = runner_data.get("total_runners", 0)
        
        # New features statistics
        total_codespaces = 0
        active_codespaces = 0
        total_open_issues = 0
        total_open_prs = 0
        total_packages = 0
        token_scopes_count = 0
        
        if resources_data:
            # Codespaces
            if "codespaces" in resources_data:
                codespaces_summary = resources_data["codespaces"].get("summary", {})
                total_codespaces = codespaces_summary.get("total_codespaces", 0)
                active_codespaces = codespaces_summary.get("active_codespaces", 0)
            
            # Issues/PRs
            if "issues_prs" in resources_data:
                for org_data in resources_data["issues_prs"].values():
                    summary = org_data.get("summary", {})
                    total_open_issues += summary.get("total_open_issues", 0)
                    total_open_prs += summary.get("total_open_prs", 0)
            
            # Packages
            if "packages" in resources_data:
                packages_summary = resources_data["packages"].get("summary", {})
                total_packages = packages_summary.get("total_user_packages", 0) + packages_summary.get("total_org_packages", 0)
            
            # Token metadata
            if "token_metadata" in resources_data:
                token_metadata = resources_data["token_metadata"]
                token_scopes_count = len(token_metadata.get("scopes", []))
        
        # Risk score display
        risk_display = ""
        if overall_risk:
            risk_score = overall_risk.get("overall_risk_score", 0)
            risk_level = overall_risk.get("risk_level", "medium")
            # Handle both string and RiskLevel enum
            if hasattr(risk_level, 'value'):
                risk_level = risk_level.value
            risk_level = str(risk_level).lower() if isinstance(risk_level, str) else "medium"
            risk_level_upper = risk_level.upper() if isinstance(risk_level, str) else str(risk_level).upper()
            risk_display = f"""
                <div class="stat-card" style="background: linear-gradient(135deg, {'#dc2626' if risk_level == 'critical' else '#f59e0b' if risk_level == 'high' else '#3b82f6' if risk_level == 'medium' else '#10b981'} 0%, {'#b91c1c' if risk_level == 'critical' else '#d97706' if risk_level == 'high' else '#2563eb' if risk_level == 'medium' else '#059669'} 100%);">
                    <h3>{risk_score}</h3>
                    <p>Overall Risk Score</p>
                    <p style="font-size: 0.8em; margin-top: 5px; opacity: 0.9;">{risk_level_upper}</p>
                </div>
            """
        
        return f"""
        <section id="executive-summary">
            <h2>
                1. Executive Summary
                <button class="section-toggle" onclick="this.closest('section').querySelector('.section-content').classList.toggle('collapsed'); this.classList.toggle('collapsed');" title="Collapse/Expand Section">▼</button>
            </h2>
            <div class="section-content">
            <div class="alert alert-critical">
                <h3 style="margin-top: 0;">⚠️ SECURITY NOTICE</h3>
                <p><strong>This report contains sensitive security information about GitHub API key permissions and accessible resources.</strong></p>
                <p>Handle this document with appropriate security measures. Do not share publicly or commit to version control.</p>
            </div>
            
            {risk_display}
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{total_permissions}</h3>
                    <p>Permissions Tested</p>
                </div>
                <div class="stat-card">
                    <h3>{granted_permissions}</h3>
                    <p>Permissions Granted</p>
                </div>
                <div class="stat-card">
                    <h3>{critical_granted}</h3>
                    <p>Critical Permissions</p>
                </div>
                <div class="stat-card">
                    <h3>{total_repos}</h3>
                    <p>Accessible Repositories</p>
                </div>
                <div class="stat-card">
                    <h3>{total_secrets}</h3>
                    <p>Secrets Discovered</p>
                </div>
                <div class="stat-card">
                    <h3>{total_webhooks}</h3>
                    <p>Webhooks Found</p>
                </div>
                <div class="stat-card">
                    <h3>{total_runners}</h3>
                    <p>Runners Discovered</p>
                </div>
                <div class="stat-card">
                    <h3>{active_codespaces}</h3>
                    <p>Active Codespaces</p>
                </div>
                <div class="stat-card">
                    <h3>{total_open_issues}</h3>
                    <p>Open Issues</p>
                </div>
                <div class="stat-card">
                    <h3>{total_open_prs}</h3>
                    <p>Open PRs</p>
                </div>
                <div class="stat-card">
                    <h3>{total_packages}</h3>
                    <p>Packages</p>
                </div>
                <div class="stat-card">
                    <h3>{token_scopes_count}</h3>
                    <p>Token Scopes</p>
                </div>
            </div>
            
            <h3>Permissions Distribution</h3>
            <div style="max-width: 600px; margin: 20px 0;">
                <canvas id="permissionsDistributionChart"></canvas>
            </div>
            
            <h3>Resource Access Overview</h3>
            <div style="max-width: 600px; margin: 20px 0;">
                <canvas id="resourceAccessChart"></canvas>
            </div>
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Key Findings</h3>
                <ul>
                    <li><strong>Permission Scope:</strong> {granted_permissions} out of {total_permissions} tested permissions are granted</li>
                    <li><strong>Critical Permissions:</strong> {critical_granted} critical permissions are granted</li>
                    <li><strong>Resource Access:</strong> Access to {total_repos} repositories, {total_secrets} secrets, and {total_webhooks} webhooks</li>
                    <li><strong>Infrastructure:</strong> {total_runners} runners discovered in enterprise infrastructure</li>
                </ul>
            </div>
            </div>
        </section>
        """
    
    def _generate_permissions_section(self, permissions_data: Dict[str, Any]) -> str:
        """Generate permissions analysis section."""
        critical_perms = permissions_data.get("critical_permissions", {})
        standard_perms = permissions_data.get("standard_permissions", {})
        
        critical_rows = []
        for perm_name, perm_data in critical_perms.items():
            granted = perm_data.get("granted", False)
            message = perm_data.get("message", "")
            risk_level = "CRITICAL"
            status_badge = f'<span class="risk-badge risk-critical">{"GRANTED" if granted else "DENIED"}</span>'
            critical_rows.append(f"""
                <tr>
                    <td><code>{perm_name}</code></td>
                    <td>{status_badge}</td>
                    <td><span class="risk-badge risk-critical">{risk_level}</span></td>
                    <td>{message[:100]}...</td>
                </tr>
            """)
        
        standard_rows = []
        for perm_name, perm_data in standard_perms.items():
            granted = perm_data.get("granted", False)
            message = perm_data.get("message", "")
            risk_level = "MEDIUM"
            status_badge = f'<span class="risk-badge risk-medium">{"GRANTED" if granted else "DENIED"}</span>'
            standard_rows.append(f"""
                <tr>
                    <td><code>{perm_name}</code></td>
                    <td>{status_badge}</td>
                    <td><span class="risk-badge risk-medium">{risk_level}</span></td>
                    <td>{message[:100]}...</td>
                </tr>
            """)
        
        return f"""
        <section id="permissions-analysis">
            <h2>2. Permissions Analysis</h2>
            
            <h3>Critical Permissions ({len(critical_perms)} tested)</h3>
            <table>
                <thead>
                    <tr>
                        <th>Permission</th>
                        <th>Status</th>
                        <th>Risk Level</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(critical_rows)}
                </tbody>
            </table>
            
            <h3>Standard Permissions ({len(standard_perms)} tested)</h3>
            <table>
                <thead>
                    <tr>
                        <th>Permission</th>
                        <th>Status</th>
                        <th>Risk Level</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(standard_rows)}
                </tbody>
            </table>
        </section>
        """
    
    def _generate_resources_section(
        self,
        resources_data: Optional[Dict[str, Any]],
        enumeration_data: Optional[Dict[str, Any]]
    ) -> str:
        """Generate accessible resources section."""
        sections = []
        
        if resources_data:
            if "repositories" in resources_data:
                repos = resources_data["repositories"]
                total = repos.get("total", 0)
                user_repos = len(repos.get("user_repos", []))
                org_repos = len(repos.get("org_repos", []))
                starred = len(repos.get("starred_repos", []))
                
                sections.append(f"""
                <div class="finding-card high">
                    <h4>📦 Repositories</h4>
                    <p><strong>Total Accessible:</strong> {total}</p>
                    <ul>
                        <li>User repositories: {user_repos}</li>
                        <li>Organization repositories: {org_repos}</li>
                        <li>Starred repositories: {starred}</li>
                    </ul>
                    <p><strong>Risk:</strong> <span class="risk-badge risk-high">HIGH</span></p>
                    <p>Access to source code, commit history, and repository settings.</p>
                </div>
                """)
            
            if "projects" in resources_data:
                projects = resources_data["projects"]
                total = projects.get("total", 0)
                sections.append(f"""
                <div class="finding-card medium">
                    <h4>📋 Projects</h4>
                    <p><strong>Total Accessible:</strong> {total}</p>
                    <p><strong>Risk:</strong> <span class="risk-badge risk-medium">MEDIUM</span></p>
                </div>
                """)
            
            if "webhooks" in resources_data:
                webhooks = resources_data["webhooks"]
                total = webhooks.get("total", 0)
                sections.append(f"""
                <div class="finding-card high">
                    <h4>🔗 Webhooks</h4>
                    <p><strong>Total Discovered:</strong> {total}</p>
                    <p><strong>Risk:</strong> <span class="risk-badge risk-high">HIGH</span></p>
                    <p>Visibility into webhook configurations and endpoints.</p>
                </div>
                """)
            
            if "secrets" in resources_data:
                secrets = resources_data.get("secrets", [])
                total = len(secrets) if isinstance(secrets, list) else 0
                sections.append(f"""
                <div class="finding-card critical">
                    <h4>🔐 Secrets</h4>
                    <p><strong>Total Discovered:</strong> {total}</p>
                    <p><strong>Risk:</strong> <span class="risk-badge risk-critical">CRITICAL</span></p>
                    <p>Access to sensitive credentials, API keys, tokens, and passwords.</p>
                </div>
                """)
        
        if enumeration_data:
            repos = enumeration_data.get("repositories", [])
            if isinstance(repos, list) and len(repos) > 0:
                sections.append(f"""
                <div class="finding-card high">
                    <h4>🏢 Organization Repositories</h4>
                    <p><strong>Total:</strong> {len(repos)}</p>
                    <p><strong>Risk:</strong> <span class="risk-badge risk-high">HIGH</span></p>
                </div>
                """)
        
        if not sections:
            sections = ['<div class="alert alert-info"><p>No resource data available from the analysis.</p></div>']
        
        return f"""
        <section id="accessible-resources">
            <h2>3. Accessible Resources</h2>
            {''.join(sections)}
        </section>
        """
    
    def _generate_runner_section(self, runner_data: Dict[str, Any]) -> str:
        """Generate runner analysis section with enhanced network exposure and execution capability details."""
        total = runner_data.get("total_runners", 0)
        online = runner_data.get("online_runners", 0)
        offline = runner_data.get("offline_runners", 0)
        network_info = runner_data.get("network_info", {})
        
        ip_addresses = network_info.get("unique_ip_addresses", [])
        hostnames = network_info.get("unique_hostnames", [])
        os_dist = network_info.get("os_distribution", {})
        exposure_summary = network_info.get("network_exposure_summary", {})
        execution_capability = network_info.get("execution_capability", {})
        online_runners_with_network = network_info.get("online_runners_with_network_info", [])
        
        # Network exposure details
        exposed_runners_count = exposure_summary.get("total_exposed_runners", 0)
        online_exposed_count = exposure_summary.get("online_exposed_runners", 0)
        private_ip_count = exposure_summary.get("private_ip_count", 0)
        public_ip_count = exposure_summary.get("public_ip_count", 0)
        
        # Execution capability details
        potential_ssh_targets = execution_capability.get("potential_ssh_targets", 0)
        
        # Build IP address list HTML
        ip_list_html = ""
        if ip_addresses:
            ip_list_html = "<ul style='margin: 10px 0; padding-left: 25px;'>"
            for ip in ip_addresses[:20]:  # Show first 20
                ip_list_html += f"<li><code>{ip}</code></li>"
            if len(ip_addresses) > 20:
                ip_list_html += f"<li><em>... and {len(ip_addresses) - 20} more</em></li>"
            ip_list_html += "</ul>"
        else:
            ip_list_html = "<p style='color: #7f8c8d;'>No IP addresses detected in runner names.</p>"
        
        # Build hostname list HTML
        hostname_list_html = ""
        if hostnames:
            hostname_list_html = "<ul style='margin: 10px 0; padding-left: 25px;'>"
            for hostname in hostnames[:20]:  # Show first 20
                hostname_list_html += f"<li><code>{hostname}</code></li>"
            if len(hostnames) > 20:
                hostname_list_html += f"<li><em>... and {len(hostnames) - 20} more</em></li>"
            hostname_list_html += "</ul>"
        else:
            hostname_list_html = "<p style='color: #7f8c8d;'>No hostnames detected in runner names.</p>"
        
        # Build online runners with network info table
        runners_table_html = ""
        if online_runners_with_network:
            runners_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Runner ID</th>
                        <th>Runner Name</th>
                        <th>IP Addresses</th>
                        <th>Hostnames</th>
                        <th>OS</th>
                        <th>Architecture</th>
                    </tr>
                </thead>
                <tbody>
            """
            for runner in online_runners_with_network[:10]:  # Show first 10
                runner_id = runner.get("runner_id", "N/A")
                runner_name = runner.get("runner_name", "N/A")
                ips = runner.get("ip_addresses", [])
                hostnames_list = runner.get("hostnames", [])
                runner_os = runner.get("os", "unknown")
                arch = runner.get("architecture", "unknown")
                
                ips_display = ", ".join([f"<code>{ip}</code>" for ip in ips[:3]])
                if len(ips) > 3:
                    ips_display += f" <em>(+{len(ips) - 3} more)</em>"
                if not ips:
                    ips_display = "<em>None</em>"
                
                hostnames_display = ", ".join([f"<code>{h}</code>" for h in hostnames_list[:3]])
                if len(hostnames_list) > 3:
                    hostnames_display += f" <em>(+{len(hostnames_list) - 3} more)</em>"
                if not hostnames_list:
                    hostnames_display = "<em>None</em>"
                
                runners_table_html += f"""
                    <tr>
                        <td>{runner_id}</td>
                        <td><code>{runner_name[:40]}{'...' if len(runner_name) > 40 else ''}</code></td>
                        <td>{ips_display}</td>
                        <td>{hostnames_display}</td>
                        <td>{runner_os}</td>
                        <td>{arch}</td>
                    </tr>
                """
            runners_table_html += """
                </tbody>
            </table>
            """
            if len(online_runners_with_network) > 10:
                runners_table_html += f"<p style='margin-top: 10px; color: #7f8c8d;'><em>Showing 10 of {len(online_runners_with_network)} online runners with network information.</em></p>"
        else:
            runners_table_html = "<p style='color: #7f8c8d;'>No online runners with detectable network information.</p>"
        
        return f"""
        <section id="runner-analysis">
            <h2>4. Runner Infrastructure Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{total}</h3>
                    <p>Total Runners</p>
                </div>
                <div class="stat-card">
                    <h3>{online}</h3>
                    <p>Online Runners</p>
                </div>
                <div class="stat-card">
                    <h3>{offline}</h3>
                    <p>Offline Runners</p>
                </div>
                <div class="stat-card">
                    <h3>{len(ip_addresses)}</h3>
                    <p>IP Addresses</p>
                </div>
                <div class="stat-card">
                    <h3>{len(hostnames)}</h3>
                    <p>Hostnames</p>
                </div>
                <div class="stat-card">
                    <h3>{online_exposed_count}</h3>
                    <p>Online Exposed</p>
                </div>
            </div>
            
            <h3>Network Exposure Analysis</h3>
            <div class="summary-box">
                <h4>Exposure Summary</h4>
                <ul>
                    <li><strong>Total Runners with Network Exposure:</strong> {exposed_runners_count}</li>
                    <li><strong>Online Runners with Network Exposure:</strong> {online_exposed_count}</li>
                    <li><strong>Unique IP Addresses Discovered:</strong> {len(ip_addresses)}</li>
                    <li><strong>Private IP Addresses:</strong> {private_ip_count}</li>
                    <li><strong>Public IP Addresses:</strong> {public_ip_count}</li>
                    <li><strong>Unique Hostnames Discovered:</strong> {len(hostnames)}</li>
                </ul>
            </div>
            
            <h4>Discovered IP Addresses</h4>
            {ip_list_html}
            
            <h4>Discovered Hostnames</h4>
            {hostname_list_html}
            
            <h3>Execution Capability Assessment</h3>
            <div class="alert alert-{'critical' if potential_ssh_targets > 0 and online_exposed_count > 5 else 'high' if potential_ssh_targets > 0 else 'medium' if online_exposed_count > 0 else 'info'}">
                <h4 style="margin-top: 0;">Execution Capability Analysis</h4>
                <ul>
                    <li><strong>Online Runners:</strong> {online}</li>
                    <li><strong>Runners with Network Information:</strong> {potential_ssh_targets}</li>
                    <li><strong>Potential SSH Targets:</strong> {potential_ssh_targets} online runners with detectable IP addresses or hostnames</li>
                    <li><strong>Risk Level:</strong> {'HIGH' if potential_ssh_targets > 0 and online_exposed_count > 5 else 'MEDIUM' if potential_ssh_targets > 0 else 'LOW' if online_exposed_count > 0 else 'NONE'}</li>
                </ul>
            </div>
            
            <h4>Online Runners with Network Information</h4>
            {runners_table_html}
            
            <h3>Runner Status Distribution</h3>
            <div style="max-width: 600px; margin: 20px 0;">
                <canvas id="runnerStatusChart"></canvas>
            </div>
            
            <h3>OS Distribution Chart</h3>
            <div style="max-width: 600px; margin: 20px 0;">
                <canvas id="runnerOSChart"></canvas>
            </div>
            
            <h3>Network Exposure Visualization</h3>
            <div style="max-width: 600px; margin: 20px 0;">
                <canvas id="networkExposureChart"></canvas>
            </div>
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Security Implications</h3>
                <ul>
                    <li><strong>Network Exposure:</strong> {exposed_runners_count} runners expose IP addresses or hostnames in their names, making them potentially identifiable and targetable on the network.</li>
                    <li><strong>Execution Capability:</strong> {potential_ssh_targets} online runners have detectable network information, enabling potential remote command execution if SSH access is configured.</li>
                    <li><strong>Risk Assessment:</strong> The combination of exposed network information and online status creates a security risk if proper access controls are not in place.</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_security_findings(
        self,
        permissions_data: Optional[Dict[str, Any]],
        resources_data: Optional[Dict[str, Any]],
        runner_data: Optional[Dict[str, Any]]
    ) -> str:
        """Generate security findings section."""
        findings = []
        
        if permissions_data:
            critical_perms = permissions_data.get("critical_permissions", {})
            for perm_name, perm_data in critical_perms.items():
                if perm_data.get("granted", False):
                    if "admin:org" in perm_name or "admin:enterprise" in perm_name:
                        findings.append(("CRITICAL", f"Organization/Enterprise administration permission granted: <code>{perm_name}</code>"))
                    elif "delete" in perm_name.lower():
                        findings.append(("CRITICAL", f"Deletion permission granted: <code>{perm_name}</code>"))
                    elif "secret" in perm_name.lower():
                        findings.append(("CRITICAL", f"Secrets access permission granted: <code>{perm_name}</code>"))
                    elif "hook" in perm_name.lower():
                        findings.append(("HIGH", f"Webhook management permission granted: <code>{perm_name}</code>"))
        
        if resources_data:
            if "secrets" in resources_data:
                secrets = resources_data.get("secrets", [])
                if isinstance(secrets, list) and len(secrets) > 0:
                    findings.append(("CRITICAL", f"Access to {len(secrets)} organization secrets discovered"))
        
        if runner_data:
            network_info = runner_data.get("network_info", {})
            online = runner_data.get("online_runners", 0)
            exposure_summary = network_info.get("network_exposure_summary", {})
            execution_capability = network_info.get("execution_capability", {})
            
            online_exposed = exposure_summary.get("online_exposed_runners", 0)
            potential_targets = execution_capability.get("potential_ssh_targets", 0)
            public_ips = exposure_summary.get("public_ip_count", 0)
            
            if online > 0:
                if potential_targets > 0 and public_ips > 0:
                    findings.append(("CRITICAL", f"{potential_targets} online runners with exposed public IP addresses - high risk for remote execution"))
                elif potential_targets > 0:
                    findings.append(("HIGH", f"{potential_targets} online runners with network exposure - potential for remote command execution"))
                elif online_exposed > 0:
                    findings.append(("HIGH", f"{online_exposed} online runners with network information exposure"))
                else:
                    findings.append(("MEDIUM", f"{online} online runners discovered"))
        
        critical_findings = [f for f in findings if f[0] == "CRITICAL"]
        high_findings = [f for f in findings if f[0] == "HIGH"]
        
        critical_html = "".join([f"<li>{f[1]}</li>" for f in critical_findings])
        high_html = "".join([f"<li>{f[1]}</li>" for f in high_findings])
        
        return f"""
        <section id="security-findings">
            <h2>20. Security Findings</h2>
            
            {f'<div class="alert alert-critical"><h3 style="margin-top: 0;">🔴 Critical Findings</h3><ul>{critical_html}</ul></div>' if critical_findings else ''}
            {f'<div class="alert alert-high"><h3 style="margin-top: 0;">🟡 High-Risk Findings</h3><ul>{high_html}</ul></div>' if high_findings else ''}
            
            {f'<div class="alert alert-info"><p style="margin: 0;">No critical or high-risk findings identified based on the analysis.</p></div>' if not findings else ''}
        </section>
        """
    
    def _generate_test_results_section(self, test_results: Dict[str, Any]) -> str:
        """Generate test results section."""
        summary = test_results.get("summary", {})
        total = summary.get("total_tests", 0)
        passed = summary.get("passed", 0)
        failed = summary.get("failed", 0)
        success_rate = summary.get("success_rate", 0)
        
        tests = test_results.get("tests", {})
        test_rows = []
        for test_name, test_data in tests.items():
            success = test_data.get("success", False)
            message = test_data.get("message", "")
            status = "✓ PASS" if success else "✗ FAIL"
            status_class = "granted" if success else "denied"
            test_rows.append(f"""
                <tr>
                    <td>{test_name.replace('_', ' ').title()}</td>
                    <td><span class="permission-item {status_class}">{status}</span></td>
                    <td>{message}</td>
                </tr>
            """)
        
        return f"""
        <section id="test-results">
            <h2>21. Test Suite Results</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{total}</h3>
                    <p>Total Tests</p>
                </div>
                <div class="stat-card">
                    <h3>{passed}</h3>
                    <p>Passed</p>
                </div>
                <div class="stat-card">
                    <h3>{failed}</h3>
                    <p>Failed</p>
                </div>
                <div class="stat-card">
                    <h3>{success_rate:.1f}%</h3>
                    <p>Success Rate</p>
                </div>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>Test</th>
                        <th>Status</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(test_rows)}
                </tbody>
            </table>
        </section>
        """
    
    def _generate_rate_limit_section(self, rate_limit_data: Dict[str, Any]) -> str:
        """Generate rate limit monitoring section."""
        core = rate_limit_data.get("core", {})
        search = rate_limit_data.get("search", {})
        graphql = rate_limit_data.get("graphql", {})
        
        limit = core.get("limit", 0)
        remaining = core.get("remaining", 0)
        used = core.get("used", 0)
        usage_percent = core.get("usage_percent", 0)
        status = core.get("status", "unknown")
        time_until_reset = core.get("time_until_reset", 0)
        recommendations = rate_limit_data.get("recommendations", [])
        
        status_class = {
            "critical": "alert-critical",
            "warning": "alert-high",
            "healthy": "alert-info"
        }.get(status, "alert-medium")
        
        recommendations_html = ""
        if recommendations:
            recommendations_html = "<ul>"
            for rec in recommendations:
                recommendations_html += f"<li>{rec}</li>"
            recommendations_html += "</ul>"
        
        return f"""
        <section id="rate-limit-monitoring">
            <h2>53. Rate Limit Monitoring</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{limit}</h3>
                    <p>Total Limit</p>
                </div>
                <div class="stat-card">
                    <h3>{remaining}</h3>
                    <p>Remaining</p>
                </div>
                <div class="stat-card">
                    <h3>{used}</h3>
                    <p>Used</p>
                </div>
                <div class="stat-card">
                    <h3>{usage_percent:.1f}%</h3>
                    <p>Usage</p>
                </div>
            </div>
            
            <div class="alert {status_class}">
                <h3 style="margin-top: 0;">Rate Limit Status: {status.upper()}</h3>
                <p>Current rate limit usage: {used} of {limit} requests used ({usage_percent:.1f}%)</p>
                <p>Remaining requests: {remaining}</p>
                {f'<p>Rate limit resets in: {int(time_until_reset / 60)} minutes</p>' if time_until_reset > 0 else ''}
            </div>
            
            <h3>Resource-Specific Limits</h3>
            <table>
                <thead>
                    <tr>
                        <th>Resource</th>
                        <th>Limit</th>
                        <th>Remaining</th>
                        <th>Reset Time</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>Core API</strong></td>
                        <td>{core.get('limit', 0)}</td>
                        <td>{core.get('remaining', 0)}</td>
                        <td>{core.get('reset_time', 'N/A')}</td>
                    </tr>
                    <tr>
                        <td><strong>Search API</strong></td>
                        <td>{search.get('limit', 0)}</td>
                        <td>{search.get('remaining', 0)}</td>
                        <td>{search.get('reset_time', 'N/A')}</td>
                    </tr>
                    <tr>
                        <td><strong>GraphQL API</strong></td>
                        <td>{graphql.get('limit', 0)}</td>
                        <td>{graphql.get('remaining', 0)}</td>
                        <td>{graphql.get('reset_time', 'N/A')}</td>
                    </tr>
                </tbody>
            </table>
            
            {f'<h3>Recommendations</h3>{recommendations_html}' if recommendations_html else ''}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Rate Limit Best Practices</h3>
                <ul>
                    <li><strong>Caching:</strong> Implement response caching to reduce API calls</li>
                    <li><strong>Request Batching:</strong> Batch multiple requests when possible</li>
                    <li><strong>Conditional Requests:</strong> Use ETags and conditional requests to avoid unnecessary calls</li>
                    <li><strong>Monitoring:</strong> Monitor rate limit usage to avoid hitting limits</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_drift_detection_section(self, drift_data: Dict[str, Any]) -> str:
        """Generate permission drift detection section."""
        has_changes = drift_data.get("has_changes", False)
        change_count = drift_data.get("change_count", 0)
        changes = drift_data.get("changes", [])
        critical_changes = drift_data.get("critical_changes", [])
        high_changes = drift_data.get("high_changes", [])
        summary_changes = drift_data.get("summary_changes", {})
        previous_snapshot_time = drift_data.get("previous_snapshot_time")
        
        changes_html = ""
        if changes:
            changes_html = """
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Permission</th>
                        <th>Previous Status</th>
                        <th>Current Status</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
            """
            for change in changes[:20]:  # Show first 20
                changes_html += f"""
                    <tr>
                        <td>{change.get('type', 'unknown').replace('_', ' ').title()}</td>
                        <td><code>{change.get('permission', 'N/A')}</code></td>
                        <td>{change.get('previous_status', 'N/A')}</td>
                        <td>{change.get('current_status', 'N/A')}</td>
                        <td><span class="risk-badge risk-{change.get('severity', 'medium')}">{change.get('severity', 'medium').upper()}</span></td>
                    </tr>
                """
            changes_html += """
                </tbody>
            </table>
            """
            if len(changes) > 20:
                changes_html += f"<p style='margin-top: 10px; color: #7f8c8d;'><em>Showing 20 of {len(changes)} changes.</em></p>"
        else:
            changes_html = "<p style='color: #7f8c8d;'>No permission changes detected.</p>"
        
        status_class = "alert-critical" if critical_changes else "alert-high" if high_changes else "alert-info"
        
        return f"""
        <section id="permission-drift">
            <h2>54. Permission Drift Detection</h2>
            
            <div class="alert {status_class}">
                <h3 style="margin-top: 0;">{'⚠️ Permission Changes Detected' if has_changes else '✓ No Changes Detected'}</h3>
                <p><strong>Total Changes:</strong> {change_count}</p>
                <p><strong>Critical Changes:</strong> {len(critical_changes)}</p>
                <p><strong>High Priority Changes:</strong> {len(high_changes)}</p>
                {f'<p><strong>Previous Snapshot:</strong> {previous_snapshot_time}</p>' if previous_snapshot_time else '<p><strong>Previous Snapshot:</strong> None (first run)</p>'}
            </div>
            
            <h3>Summary Changes</h3>
            <table>
                <thead>
                    <tr>
                        <th>Metric</th>
                        <th>Change</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Total Tested</td>
                        <td>{summary_changes.get('total_tested', 0):+d}</td>
                    </tr>
                    <tr>
                        <td>Granted Permissions</td>
                        <td>{summary_changes.get('granted', 0):+d}</td>
                    </tr>
                    <tr>
                        <td>Critical Permissions Granted</td>
                        <td>{summary_changes.get('critical_granted', 0):+d}</td>
                    </tr>
                </tbody>
            </table>
            
            <h3>Permission Changes</h3>
            {changes_html}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Drift Detection Security Considerations</h3>
                <ul>
                    <li><strong>Permission Creep:</strong> Monitor for gradual increase in permissions over time</li>
                    <li><strong>Unauthorized Changes:</strong> Investigate any unexpected permission grants</li>
                    <li><strong>Regular Audits:</strong> Run drift detection regularly to catch changes early</li>
                    <li><strong>Change Tracking:</strong> Maintain history of permission changes for compliance</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_compliance_section(self, compliance_data: Dict[str, Any]) -> str:
        """Generate compliance checking section."""
        overall_compliant = compliance_data.get("overall_compliant", False)
        frameworks = compliance_data.get("frameworks", {})
        
        frameworks_html = ""
        for framework_name, framework_data in frameworks.items():
            compliant = framework_data.get("compliant", False)
            score = framework_data.get("compliance_score", 0)
            findings = framework_data.get("findings", [])
            
            status_class = "alert-info" if compliant else "alert-high"
            status_icon = "✓" if compliant else "⚠️"
            
            findings_html = ""
            if findings:
                # Define finding class mapping outside f-string
                finding_class_map = {
                    "compliant": "alert-info",
                    "non_compliant": "alert-critical",
                    "warning": "alert-high",
                    "info": "alert-medium"
                }
                
                findings_html = "<ul>"
                for finding in findings:
                    finding_status = finding.get("status", "unknown")
                    finding_severity = finding.get("severity", "medium")
                    finding_desc = finding.get("description", "")
                    finding_req = finding.get("requirement", "")
                    
                    finding_class = finding_class_map.get(finding_status, "alert-medium")
                    
                    findings_html += f"""
                    <li class="alert {finding_class}" style="margin: 10px 0; padding: 10px;">
                        <strong>{finding_req}:</strong> {finding_desc}
                        <br><small>Status: {finding_status.replace('_', ' ').title()} | Severity: {finding_severity.upper()}</small>
                    </li>
                    """
                findings_html += "</ul>"
            else:
                findings_html = "<p style='color: #7f8c8d;'>No specific findings.</p>"
            
            frameworks_html += f"""
            <div class="summary-box" style="margin: 20px 0;">
                <h3>{status_icon} {framework_name}</h3>
                <p><strong>Compliance Status:</strong> {'COMPLIANT' if compliant else 'NON-COMPLIANT'}</p>
                <p><strong>Compliance Score:</strong> {score}/100</p>
                <h4>Findings:</h4>
                {findings_html}
            </div>
            """
        
        return f"""
        <section id="compliance-checking">
            <h2>55. Compliance Checking</h2>
            
            <div class="alert {'alert-info' if overall_compliant else 'alert-high'}">
                <h3 style="margin-top: 0;">{'✓ Overall Compliance: COMPLIANT' if overall_compliant else '⚠️ Overall Compliance: NON-COMPLIANT'}</h3>
                <p>Checked against {len(frameworks)} compliance framework(s)</p>
            </div>
            
            <h3>Framework Results</h3>
            {frameworks_html}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Compliance Notes</h3>
                <ul>
                    <li><strong>Framework Coverage:</strong> Results are based on automated checks and may require manual verification</li>
                    <li><strong>Continuous Monitoring:</strong> Regular compliance checks help maintain security posture</li>
                    <li><strong>Remediation:</strong> Address non-compliant findings to improve security posture</li>
                    <li><strong>Documentation:</strong> Maintain evidence of compliance for audit purposes</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_remediation_section(self, remediation_data: Dict[str, Any]) -> str:
        """Generate automated remediation suggestions section."""
        summary = remediation_data.get("summary", {})
        total = summary.get("total", 0)
        by_priority = summary.get("by_priority", {})
        by_category = summary.get("by_category", {})
        estimated_effort = summary.get("estimated_effort", {})
        
        # Build remediation cards by priority
        remediations_html = ""
        for priority in ["critical", "high", "medium", "low", "info"]:
            items = remediation_data.get(priority, [])
            if not items:
                continue
            
            priority_class = {
                "critical": "alert-critical",
                "high": "alert-high",
                "medium": "alert-medium",
                "low": "alert-low",
                "info": "alert-info"
            }.get(priority, "alert-medium")
            
            priority_title = priority.upper()
            remediations_html += f"""
            <div class="remediation-priority-group" style="margin: 30px 0;">
                <h3 style="color: {'#dc2626' if priority == 'critical' else '#ea580c' if priority == 'high' else '#d97706' if priority == 'medium' else '#65a30d' if priority == 'low' else '#0891b2'};">
                    {priority_title} Priority ({len(items)} items)
                </h3>
            """
            
            for item in items:
                item_id = item.get("id", "unknown")
                title = item.get("title", "Untitled")
                description = item.get("description", "")
                category = item.get("category", "unknown").replace("_", " ").title()
                effort = item.get("effort", "medium").title()
                impact = item.get("impact", "medium").title()
                steps = item.get("steps", [])
                commands = item.get("commands", [])
                references = item.get("references", [])
                
                steps_html = ""
                if steps:
                    steps_html = "<ol style='margin: 10px 0; padding-left: 25px;'>"
                    for step in steps:
                        steps_html += f"<li style='margin: 5px 0;'>{step}</li>"
                    steps_html += "</ol>"
                
                commands_html = ""
                if commands:
                    commands_html = "<div style='background: #1e293b; padding: 15px; border-radius: 5px; margin: 10px 0;'>"
                    commands_html += "<pre style='color: #e2e8f0; margin: 0; font-family: monospace; font-size: 0.9em; white-space: pre-wrap;'>"
                    for cmd in commands:
                        commands_html += f"{cmd}\n"
                    commands_html += "</pre></div>"
                
                references_html = ""
                if references:
                    references_html = "<div style='margin-top: 10px;'>"
                    references_html += "<strong>References:</strong><ul style='margin: 5px 0; padding-left: 25px;'>"
                    for ref in references:
                        references_html += f"<li><a href='{ref}' target='_blank' style='color: #3b82f6;'>{ref}</a></li>"
                    references_html += "</ul></div>"
                
                remediations_html += f"""
                <div class="remediation-card" style="border-left: 4px solid {'#dc2626' if priority == 'critical' else '#ea580c' if priority == 'high' else '#d97706' if priority == 'medium' else '#65a30d' if priority == 'low' else '#0891b2'}; padding: 20px; margin: 15px 0; background: #f8fafc; border-radius: 5px;">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;">
                        <h4 style="margin: 0; color: #1e293b;">{title}</h4>
                        <div style="display: flex; gap: 10px;">
                            <span class="risk-badge risk-{priority}" style="font-size: 0.8em;">{priority.upper()}</span>
                            <span style="font-size: 0.8em; color: #64748b;">{category}</span>
                        </div>
                    </div>
                    <p style="color: #475569; margin: 10px 0;">{description}</p>
                    <div style="display: flex; gap: 15px; margin: 10px 0; font-size: 0.9em; color: #64748b;">
                        <span><strong>Effort:</strong> {effort}</span>
                        <span><strong>Impact:</strong> {impact}</span>
                        <span><strong>ID:</strong> {item_id}</span>
                    </div>
                    {f'<div style="margin: 15px 0;"><strong>Steps to Remediate:</strong>{steps_html}</div>' if steps_html else ''}
                    {commands_html}
                    {references_html}
                </div>
                """
            
            remediations_html += "</div>"
        
        # Summary statistics
        summary_html = f"""
        <div class="stats" style="margin: 20px 0;">
            <div class="stat-card">
                <h3>{total}</h3>
                <p>Total Remediations</p>
            </div>
            <div class="stat-card">
                <h3>{by_priority.get('critical', 0)}</h3>
                <p>Critical</p>
            </div>
            <div class="stat-card">
                <h3>{by_priority.get('high', 0)}</h3>
                <p>High Priority</p>
            </div>
            <div class="stat-card">
                <h3>{estimated_effort.get('low', 0) + estimated_effort.get('medium', 0)}</h3>
                <p>Quick Wins</p>
            </div>
        </div>
        """
        
        return f"""
        <section id="automated-remediation">
            <h2>56. Automated Remediation Suggestions</h2>
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">🔧 Actionable Remediation Steps</h3>
                <p>This section provides prioritized, step-by-step remediation guidance based on your security findings. 
                Each remediation includes detailed steps, commands, and references to help you address security issues effectively.</p>
            </div>
            
            {summary_html}
            
            {remediations_html if remediations_html else '<p style="color: #7f8c8d;">No remediation suggestions available.</p>'}
            
            <div class="alert alert-medium" style="margin-top: 30px;">
                <h3 style="margin-top: 0;">ℹ️ Remediation Best Practices</h3>
                <ul>
                    <li><strong>Prioritize Critical Items:</strong> Address critical and high-priority remediations first</li>
                    <li><strong>Test in Staging:</strong> Test remediation steps in a non-production environment first</li>
                    <li><strong>Document Changes:</strong> Keep a log of all remediation actions taken</li>
                    <li><strong>Verify Fixes:</strong> Re-run the security assessment after implementing remediations</li>
                    <li><strong>Schedule Reviews:</strong> Set up regular security reviews to prevent regression</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_recommendations(
        self,
        permissions_data: Optional[Dict[str, Any]],
        resources_data: Optional[Dict[str, Any]]
    ) -> str:
        """Generate recommendations section."""
        recommendations = []
        
        if permissions_data:
            critical_perms = permissions_data.get("critical_permissions", {})
            for perm_name, perm_data in critical_perms.items():
                if perm_data.get("granted", False):
                    if "admin:org" in perm_name:
                        recommendations.append("Review and restrict admin:org permission - use read-only when possible")
                    elif "delete" in perm_name.lower():
                        recommendations.append("Remove delete permissions unless absolutely necessary")
                    elif "secret" in perm_name.lower():
                        recommendations.append("Rotate all accessible secrets and implement secret access logging")
        
        if resources_data and "secrets" in resources_data:
            secrets = resources_data.get("secrets", [])
            if isinstance(secrets, list) and len(secrets) > 0:
                recommendations.append(f"Immediately rotate {len(secrets)} exposed organization secrets")
        
        rec_html = "".join([f"<li>{r}</li>" for r in recommendations]) if recommendations else "<li>No specific recommendations based on current findings.</li>"
        
        return f"""
        <section id="recommendations">
            <h2>22. Security Recommendations</h2>
            
            <div class="recommendations">
                <h3>⚠️ Immediate Actions</h3>
                <ul>
                    {rec_html}
                    <li>Review all granted permissions and remove unnecessary ones</li>
                    <li>Enable audit logging for all sensitive operations</li>
                    <li>Implement least privilege principle</li>
                    <li>Regularly rotate API keys and secrets</li>
                    <li>Monitor API key usage and access patterns</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_actions_section(self, actions_data: Dict[str, Any]) -> str:
        """Generate GitHub Actions detection section."""
        summary = actions_data.get("summary", {})
        repos = actions_data.get("repositories", {})
        orgs = actions_data.get("organizations", {})
        
        total_repos = summary.get("total_repos_with_actions", 0)
        total_workflows = summary.get("total_workflows", 0)
        total_runs = summary.get("total_runs", 0)
        total_artifacts = summary.get("total_artifacts", 0)
        total_secrets = summary.get("total_secrets", 0)
        total_orgs = summary.get("total_orgs_with_actions", 0)
        
        # Build repositories table
        repos_table_html = ""
        if repos:
            repos_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Repository</th>
                        <th>Workflows</th>
                        <th>Runs</th>
                        <th>Artifacts</th>
                        <th>Secrets</th>
                        <th>Runners</th>
                    </tr>
                </thead>
                <tbody>
            """
            for repo_name, repo_data in list(repos.items())[:20]:  # Show first 20
                usage = repo_data.get("usage", {})
                repos_table_html += f"""
                    <tr>
                        <td><code>{repo_name}</code></td>
                        <td>{usage.get('total_workflows', 0)}</td>
                        <td>{usage.get('total_runs', 0)}</td>
                        <td>{usage.get('total_artifacts', 0)}</td>
                        <td>{usage.get('total_secrets', 0)}</td>
                        <td>{usage.get('total_runners', 0)}</td>
                    </tr>
                """
            repos_table_html += """
                </tbody>
            </table>
            """
            if len(repos) > 20:
                repos_table_html += f"<p style='margin-top: 10px; color: #7f8c8d;'><em>Showing 20 of {len(repos)} repositories with Actions.</em></p>"
        else:
            repos_table_html = "<p style='color: #7f8c8d;'>No repositories with GitHub Actions detected.</p>"
        
        # Build organizations table
        orgs_table_html = ""
        if orgs:
            orgs_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Secrets</th>
                        <th>Variables</th>
                        <th>Runners</th>
                        <th>Runner Groups</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_name, org_data in list(orgs.items())[:20]:  # Show first 20
                usage = org_data.get("usage", {})
                orgs_table_html += f"""
                    <tr>
                        <td><code>{org_name}</code></td>
                        <td>{usage.get('total_secrets', 0)}</td>
                        <td>{usage.get('total_variables', 0)}</td>
                        <td>{usage.get('total_runners', 0)}</td>
                        <td>{usage.get('total_runner_groups', 0)}</td>
                    </tr>
                """
            orgs_table_html += """
                </tbody>
            </table>
            """
            if len(orgs) > 20:
                orgs_table_html += f"<p style='margin-top: 10px; color: #7f8c8d;'><em>Showing 20 of {len(orgs)} organizations with Actions.</em></p>"
        else:
            orgs_table_html = "<p style='color: #7f8c8d;'>No organizations with GitHub Actions detected.</p>"
        
        return f"""
        <section id="github-actions">
            <h2>5. GitHub Actions Detection</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{total_repos}</h3>
                    <p>Repos with Actions</p>
                </div>
                <div class="stat-card">
                    <h3>{total_workflows}</h3>
                    <p>Total Workflows</p>
                </div>
                <div class="stat-card">
                    <h3>{total_runs}</h3>
                    <p>Workflow Runs</p>
                </div>
                <div class="stat-card">
                    <h3>{total_artifacts}</h3>
                    <p>Artifacts</p>
                </div>
                <div class="stat-card">
                    <h3>{total_secrets}</h3>
                    <p>Actions Secrets</p>
                </div>
                <div class="stat-card">
                    <h3>{total_orgs}</h3>
                    <p>Orgs with Actions</p>
                </div>
            </div>
            
            <h3>Repository Actions</h3>
            {repos_table_html}
            
            <h3>Organization Actions</h3>
            {orgs_table_html}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Actions Security Considerations</h3>
                <ul>
                    <li><strong>Secrets Exposure:</strong> {total_secrets} Actions secrets discovered across repositories and organizations</li>
                    <li><strong>Artifact Access:</strong> {total_artifacts} artifacts may contain sensitive build outputs</li>
                    <li><strong>Workflow Permissions:</strong> Review workflow permissions to ensure least privilege</li>
                    <li><strong>Runner Security:</strong> Self-hosted runners may expose network infrastructure</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_organizations_section(self, enumeration_data: Dict[str, Any]) -> str:
        """Generate all organizations section."""
        orgs = enumeration_data.get("organizations", [])
        summary = enumeration_data.get("summary", {})
        
        total_orgs = len(orgs)
        total_members = summary.get("total_members", 0)
        total_repos = summary.get("total_repos", 0)
        total_teams = summary.get("total_teams", 0)
        total_secrets = summary.get("total_secrets", 0)
        total_runners = summary.get("total_runners", 0)
        
        # Build organizations table
        orgs_table_html = ""
        if orgs:
            orgs_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Members</th>
                        <th>Repositories</th>
                        <th>Teams</th>
                        <th>Secrets</th>
                        <th>Runners</th>
                        <th>Packages</th>
                        <th>Installations</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org in orgs[:30]:  # Show first 30
                org_name = org.get("organization_name", "N/A")
                org_info = org.get("organization_info", {})
                enhanced = org.get("enhanced_info", {})
                
                orgs_table_html += f"""
                    <tr>
                        <td><code>{org_name}</code></td>
                        <td>{len(org.get('members', []))}</td>
                        <td>{len(org.get('repositories', []))}</td>
                        <td>{len(org.get('teams', []))}</td>
                        <td>{len(org.get('secrets', []))}</td>
                        <td>{len(org.get('organization_runners', []))}</td>
                        <td>{len(enhanced.get('packages', []))}</td>
                        <td>{len(enhanced.get('installations', []))}</td>
                    </tr>
                """
            orgs_table_html += """
                </tbody>
            </table>
            """
            if len(orgs) > 30:
                orgs_table_html += f"<p style='margin-top: 10px; color: #7f8c8d;'><em>Showing 30 of {len(orgs)} accessible organizations.</em></p>"
        else:
            orgs_table_html = "<p style='color: #7f8c8d;'>No organizations data available.</p>"
        
        return f"""
        <section id="all-organizations">
            <h2>6. All Accessible Organizations</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{total_orgs}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{total_members}</h3>
                    <p>Total Members</p>
                </div>
                <div class="stat-card">
                    <h3>{total_repos}</h3>
                    <p>Total Repositories</p>
                </div>
                <div class="stat-card">
                    <h3>{total_teams}</h3>
                    <p>Total Teams</p>
                </div>
                <div class="stat-card">
                    <h3>{total_secrets}</h3>
                    <p>Total Secrets</p>
                </div>
                <div class="stat-card">
                    <h3>{total_runners}</h3>
                    <p>Total Runners</p>
                </div>
            </div>
            
            <h3>Organization Details</h3>
            {orgs_table_html}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Organization Access Summary</h3>
                <ul>
                    <li><strong>Total Organizations:</strong> Access to {total_orgs} organizations</li>
                    <li><strong>Total Members:</strong> {total_members} members across all organizations</li>
                    <li><strong>Total Repositories:</strong> {total_repos} repositories accessible</li>
                    <li><strong>Total Secrets:</strong> {total_secrets} organization secrets accessible</li>
                    <li><strong>Total Runners:</strong> {total_runners} runners across organizations</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_security_analysis_section(self, security_data: Dict[str, Any]) -> str:
        """Generate security analysis section."""
        summary = security_data.get("summary", {})
        repos = security_data.get("repositories", {})
        
        total_repos = summary.get("total_repos_analyzed", 0)
        total_code_alerts = summary.get("total_code_scanning_alerts", 0)
        total_secret_alerts = summary.get("total_secret_scanning_alerts", 0)
        total_dependabot = summary.get("total_dependabot_alerts", 0)
        repos_with_vulns = summary.get("repos_with_vulnerabilities", 0)
        repos_with_secrets = summary.get("repos_with_secrets_exposed", 0)
        repos_with_code_issues = summary.get("repos_with_code_issues", 0)
        repos_with_protection = summary.get("repos_with_branch_protection", 0)
        
        # Build security issues table
        security_table_html = ""
        if repos:
            security_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Repository</th>
                        <th>Code Alerts</th>
                        <th>Secret Alerts</th>
                        <th>Dependabot</th>
                        <th>Branch Protection</th>
                        <th>Vulnerability Alerts</th>
                    </tr>
                </thead>
                <tbody>
            """
            for repo_name, repo_data in list(repos.items())[:20]:  # Show first 20
                code_count = len(repo_data.get("code_scanning_alerts", []))
                secret_count = len(repo_data.get("secret_scanning_alerts", []))
                dependabot_count = len(repo_data.get("dependabot_alerts", []))
                has_protection = "Yes" if repo_data.get("branch_protection") else "No"
                vuln_alerts = "Yes" if repo_data.get("vulnerability_alerts") else "No"
                
                security_table_html += f"""
                    <tr>
                        <td><code>{repo_name}</code></td>
                        <td>{code_count}</td>
                        <td>{secret_count}</td>
                        <td>{dependabot_count}</td>
                        <td>{has_protection}</td>
                        <td>{vuln_alerts}</td>
                    </tr>
                """
            security_table_html += """
                </tbody>
            </table>
            """
            if len(repos) > 20:
                security_table_html += f"<p style='margin-top: 10px; color: #7f8c8d;'><em>Showing 20 of {len(repos)} analyzed repositories.</em></p>"
        else:
            security_table_html = "<p style='color: #7f8c8d;'>No security analysis data available.</p>"
        
        return f"""
        <section id="security-analysis">
            <h2>7. Security Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{total_repos}</h3>
                    <p>Repos Analyzed</p>
                </div>
                <div class="stat-card">
                    <h3>{total_code_alerts}</h3>
                    <p>Code Alerts</p>
                </div>
                <div class="stat-card">
                    <h3>{total_secret_alerts}</h3>
                    <p>Secret Alerts</p>
                </div>
                <div class="stat-card">
                    <h3>{total_dependabot}</h3>
                    <p>Dependabot Alerts</p>
                </div>
                <div class="stat-card">
                    <h3>{repos_with_vulns}</h3>
                    <p>Repos with Vulns</p>
                </div>
                <div class="stat-card">
                    <h3>{repos_with_protection}</h3>
                    <p>Protected Branches</p>
                </div>
            </div>
            
            <h3>Security Issues by Repository</h3>
            {security_table_html}
            
            <h3>Security Alerts Distribution</h3>
            <div style="max-width: 600px; margin: 20px 0;">
                <canvas id="securityAlertsChart"></canvas>
            </div>
            
            <h3>Repository Security Status</h3>
            <div style="max-width: 600px; margin: 20px 0;">
                <canvas id="repositorySecurityChart"></canvas>
            </div>
            
            <div class="alert alert-critical">
                <h3 style="margin-top: 0;">🔴 Critical Security Findings</h3>
                <ul>
                    <li><strong>Secret Scanning Alerts:</strong> {total_secret_alerts} exposed secrets detected across {repos_with_secrets} repositories</li>
                    <li><strong>Code Scanning Alerts:</strong> {total_code_alerts} code security issues found in {repos_with_code_issues} repositories</li>
                    <li><strong>Dependabot Alerts:</strong> {total_dependabot} dependency vulnerabilities in {repos_with_vulns} repositories</li>
                    <li><strong>Branch Protection:</strong> Only {repos_with_protection} repositories have branch protection enabled</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_repository_analysis_section(self, repo_analysis_data: Dict[str, Any]) -> str:
        """Generate repository analysis section."""
        org_summaries = []
        total_collaborators = 0
        total_deployments = 0
        total_environments = 0
        total_releases = 0
        total_deploy_keys = 0
        
        for org_name, org_data in repo_analysis_data.items():
            summary = org_data.get("summary", {})
            org_summaries.append({
                "org": org_name,
                "repos": summary.get("total_repos", 0),
                "collaborators": summary.get("total_collaborators", 0),
                "deployments": summary.get("total_deployments", 0),
                "environments": summary.get("total_environments", 0),
                "releases": summary.get("total_releases", 0),
                "deploy_keys": summary.get("total_deploy_keys", 0)
            })
            total_collaborators += summary.get("total_collaborators", 0)
            total_deployments += summary.get("total_deployments", 0)
            total_environments += summary.get("total_environments", 0)
            total_releases += summary.get("total_releases", 0)
            total_deploy_keys += summary.get("total_deploy_keys", 0)
        
        # Build organization summary table
        org_table_html = ""
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Collaborators</th>
                        <th>Deployments</th>
                        <th>Environments</th>
                        <th>Releases</th>
                        <th>Deploy Keys</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{org_summary['org']}</code></td>
                        <td>{org_summary['repos']}</td>
                        <td>{org_summary['collaborators']}</td>
                        <td>{org_summary['deployments']}</td>
                        <td>{org_summary['environments']}</td>
                        <td>{org_summary['releases']}</td>
                        <td>{org_summary['deploy_keys']}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No repository analysis data available.</p>"
        
        return f"""
        <section id="repository-analysis">
            <h2>8. Repository Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{len(org_summaries)}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{total_collaborators}</h3>
                    <p>Total Collaborators</p>
                </div>
                <div class="stat-card">
                    <h3>{total_deployments}</h3>
                    <p>Total Deployments</p>
                </div>
                <div class="stat-card">
                    <h3>{total_environments}</h3>
                    <p>Environments</p>
                </div>
                <div class="stat-card">
                    <h3>{total_releases}</h3>
                    <p>Releases</p>
                </div>
                <div class="stat-card">
                    <h3>{total_deploy_keys}</h3>
                    <p>Deploy Keys</p>
                </div>
            </div>
            
            <h3>Organization Repository Summary</h3>
            {org_table_html}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Repository Security Considerations</h3>
                <ul>
                    <li><strong>Deploy Keys:</strong> {total_deploy_keys} deploy keys found - review for unauthorized access</li>
                    <li><strong>Environments:</strong> {total_environments} environments may contain secrets and protection rules</li>
                    <li><strong>Collaborators:</strong> {total_collaborators} collaborators with various permission levels</li>
                    <li><strong>Deployments:</strong> {total_deployments} deployments tracked - review deployment history</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_repository_insights_section(self, insights_data: Dict[str, Any]) -> str:
        """Generate repository insights section."""
        org_summaries = []
        total_clones = 0
        total_views = 0
        total_commits = 0
        repos_with_traffic = 0
        
        for org_name, org_data in insights_data.items():
            summary = org_data.get("summary", {})
            org_summaries.append({
                "org": org_name,
                "repos": summary.get("total_repos_analyzed", 0),
                "clones": summary.get("total_clones", 0),
                "unique_clones": summary.get("total_unique_clones", 0),
                "views": summary.get("total_views", 0),
                "unique_views": summary.get("total_unique_views", 0),
                "commits": summary.get("total_commits", 0),
                "traffic_repos": summary.get("repos_with_traffic", 0)
            })
            total_clones += summary.get("total_clones", 0)
            total_views += summary.get("total_views", 0)
            total_commits += summary.get("total_commits", 0)
            repos_with_traffic += summary.get("repos_with_traffic", 0)
        
        org_table_html = ""
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repos</th>
                        <th>Total Clones</th>
                        <th>Unique Clones</th>
                        <th>Total Views</th>
                        <th>Unique Views</th>
                        <th>Commits</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{org_summary['org']}</code></td>
                        <td>{org_summary['repos']}</td>
                        <td>{org_summary['clones']}</td>
                        <td>{org_summary['unique_clones']}</td>
                        <td>{org_summary['views']}</td>
                        <td>{org_summary['unique_views']}</td>
                        <td>{org_summary['commits']}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No repository insights data available.</p>"
        
        return f"""
        <section id="repository-insights">
            <h2>14. Repository Insights and Analytics</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{len(org_summaries)}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{total_clones}</h3>
                    <p>Total Clones</p>
                </div>
                <div class="stat-card">
                    <h3>{total_views}</h3>
                    <p>Total Views</p>
                </div>
                <div class="stat-card">
                    <h3>{total_commits}</h3>
                    <p>Total Commits</p>
                </div>
                <div class="stat-card">
                    <h3>{repos_with_traffic}</h3>
                    <p>Repos with Traffic</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {org_table_html}
            
            <h3>Traffic Overview</h3>
            <div style="max-width: 600px; margin: 20px 0;">
                <canvas id="repositoryTrafficChart"></canvas>
            </div>
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Repository Insights Security Considerations</h3>
                <ul>
                    <li><strong>Traffic Patterns:</strong> Repository traffic data reveals usage patterns and popular content</li>
                    <li><strong>Commit Activity:</strong> Commit statistics show development activity and contributor patterns</li>
                    <li><strong>Popular Paths:</strong> Most accessed files may contain sensitive information</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_enterprise_audit_log_section(self, audit_data: Dict[str, Any]) -> str:
        """Generate enterprise audit log section."""
        summary = audit_data.get("summary", {})
        total_events = summary.get("total_events", 0)
        event_types = summary.get("event_types", {})
        actions = summary.get("actions", {})
        
        # Build event types table
        event_types_html = ""
        if event_types:
            event_types_html = """
            <table>
                <thead>
                    <tr>
                        <th>Event Type</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>
            """
            for event_type, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True)[:20]:
                event_types_html += f"""
                    <tr>
                        <td>{event_type.replace('_', ' ').title()}</td>
                        <td>{count}</td>
                    </tr>
                """
            event_types_html += """
                </tbody>
            </table>
            """
        else:
            event_types_html = "<p style='color: #7f8c8d;'>No event types data available.</p>"
        
        # Prepare timeline data for chart
        events_list = audit_data.get("events", [])
        timeline_data = {}
        for event in events_list[:100]:  # Limit for performance
            timestamp = event.get("timestamp") or event.get("created_at", "")
            if timestamp:
                # Extract date (YYYY-MM-DD)
                date = timestamp.split("T")[0] if "T" in timestamp else timestamp[:10]
                timeline_data[date] = timeline_data.get(date, 0) + 1
        
        # Sort by date
        sorted_dates = sorted(timeline_data.keys())
        timeline_labels = sorted_dates
        timeline_counts = [timeline_data.get(date, 0) for date in sorted_dates]
        
        # Event types for pie chart
        event_types_sorted = sorted(event_types.items(), key=lambda x: x[1], reverse=True)[:10]
        event_type_labels = [et[0].replace('_', ' ').title() for et in event_types_sorted]
        event_type_counts = [et[1] for et in event_types_sorted]
        
        # Ensure values are safe for HTML
        total_events_str = str(total_events)
        event_types_count = len(event_types) if event_types else 0
        actions_count = len(actions) if actions else 0
        
        return f"""
        <section id="enterprise-audit-log">
            <h2>15. Enterprise Audit Log Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{total_events_str}</h3>
                    <p>Total Events</p>
                </div>
                <div class="stat-card">
                    <h3>{event_types_count}</h3>
                    <p>Event Types</p>
                </div>
                <div class="stat-card">
                    <h3>{actions_count}</h3>
                    <p>Unique Actions</p>
                </div>
            </div>
            
            {event_types_html}
            
            <h3>Event Timeline</h3>
            <div style="max-width: 800px; margin: 20px 0;">
                <canvas id="auditLogTimelineChart"></canvas>
            </div>
            
            <h3>Event Types Distribution</h3>
            <div style="max-width: 600px; margin: 20px 0;">
                <canvas id="auditLogEventTypesChart"></canvas>
            </div>
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Audit Log Security Considerations</h3>
                <ul>
                    <li><strong>Security Events:</strong> Audit logs contain security-relevant events and access patterns</li>
                    <li><strong>Access Patterns:</strong> Review access patterns for suspicious activity</li>
                    <li><strong>Permission Changes:</strong> Monitor permission changes and administrative actions</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_org_audit_log_section(self, audit_logs_data: Dict[str, Any]) -> str:
        """Generate organization audit log section."""
        org_summaries = []
        total_events = 0
        
        for org_name, org_data in audit_logs_data.items():
            summary = org_data.get("summary", {})
            org_summaries.append({
                "org": org_name,
                "events": summary.get("total_events", 0),
                "event_types": len(summary.get("event_types", {})),
                "actions": len(summary.get("actions", {})),
                "actors": len(summary.get("actors", {}))
            })
            total_events += summary.get("total_events", 0)
        
        org_table_html = ""
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Total Events</th>
                        <th>Event Types</th>
                        <th>Unique Actions</th>
                        <th>Unique Actors</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{org_summary['org']}</code></td>
                        <td>{org_summary['events']}</td>
                        <td>{org_summary['event_types']}</td>
                        <td>{org_summary['actions']}</td>
                        <td>{org_summary['actors']}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No organization audit log data available.</p>"
        
        return f"""
        <section id="org-audit-log">
            <h2>16. Organization Audit Log Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{len(org_summaries)}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{total_events}</h3>
                    <p>Total Events</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {org_table_html}
        </section>
        """
    
    def _generate_gists_section(self, gists_data: Dict[str, Any], starred_gists_data: Dict[str, Any]) -> str:
        """Generate gists analysis section."""
        summary = gists_data.get("summary", {})
        total_gists = summary.get("total_gists", 0)
        public_gists = summary.get("public_gists", 0)
        private_gists = summary.get("private_gists", 0)
        total_files = summary.get("total_files", 0)
        languages = summary.get("languages", {})
        
        # Build languages table
        languages_html = ""
        if languages:
            languages_html = """
            <table>
                <thead>
                    <tr>
                        <th>Language</th>
                        <th>Files</th>
                    </tr>
                </thead>
                <tbody>
            """
            for lang, count in sorted(languages.items(), key=lambda x: x[1], reverse=True)[:20]:
                languages_html += f"""
                    <tr>
                        <td>{lang}</td>
                        <td>{count}</td>
                    </tr>
                """
            languages_html += """
                </tbody>
            </table>
            """
        else:
            languages_html = "<p style='color: #7f8c8d;'>No language data available.</p>"
        
        return f"""
        <section id="gists-analysis">
            <h2>17. Gists Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{total_gists}</h3>
                    <p>Total Gists</p>
                </div>
                <div class="stat-card">
                    <h3>{public_gists}</h3>
                    <p>Public Gists</p>
                </div>
                <div class="stat-card">
                    <h3>{private_gists}</h3>
                    <p>Private Gists</p>
                </div>
                <div class="stat-card">
                    <h3>{total_files}</h3>
                    <p>Total Files</p>
                </div>
                <div class="stat-card">
                    <h3>{starred_gists_data.get('total', 0)}</h3>
                    <p>Starred Gists</p>
                </div>
            </div>
            
            <h3>Language Distribution</h3>
            {languages_html}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Gists Security Considerations</h3>
                <ul>
                    <li><strong>Code Snippets:</strong> Gists may contain code snippets, credentials, or sensitive information</li>
                    <li><strong>Private Gists:</strong> {private_gists} private gists may contain sensitive code</li>
                    <li><strong>Secret Exposure:</strong> Review gist contents for potential secret exposure</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_user_activity_section(self, activity_data: Dict[str, Any]) -> str:
        """Generate user activity section."""
        summary = activity_data.get("summary", {})
        profile = activity_data.get("profile", {})
        total_events = summary.get("total_events", 0)
        followers_count = summary.get("followers_count", 0)
        following_count = summary.get("following_count", 0)
        starred_repos_count = summary.get("starred_repos_count", 0)
        event_types = summary.get("event_types", {})
        
        return f"""
        <section id="user-activity">
            <h2>18. User Activity Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{profile.get('login', 'N/A')}</h3>
                    <p>User</p>
                </div>
                <div class="stat-card">
                    <h3>{total_events}</h3>
                    <p>Total Events</p>
                </div>
                <div class="stat-card">
                    <h3>{followers_count}</h3>
                    <p>Followers</p>
                </div>
                <div class="stat-card">
                    <h3>{following_count}</h3>
                    <p>Following</p>
                </div>
                <div class="stat-card">
                    <h3>{starred_repos_count}</h3>
                    <p>Starred Repos</p>
                </div>
            </div>
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ User Activity Security Considerations</h3>
                <ul>
                    <li><strong>Activity Patterns:</strong> User activity reveals behavior patterns and interests</li>
                    <li><strong>Network Analysis:</strong> Followers and following relationships reveal social network</li>
                    <li><strong>Repository Interests:</strong> Starred repositories indicate areas of interest</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_discussions_section(self, discussions_data: Dict[str, Any]) -> str:
        """Generate discussions analysis section."""
        org_summaries = []
        total_discussions = 0
        total_comments = 0
        total_participants = 0
        
        for org_name, org_data in discussions_data.items():
            summary = org_data.get("summary", {})
            org_summaries.append({
                "org": org_name,
                "repos": summary.get("total_repos_analyzed", 0),
                "discussions": summary.get("total_discussions", 0),
                "comments": summary.get("total_comments", 0),
                "categories": summary.get("total_categories", 0),
                "participants": summary.get("total_participants", 0)
            })
            total_discussions += summary.get("total_discussions", 0)
            total_comments += summary.get("total_comments", 0)
            total_participants += summary.get("total_participants", 0)
        
        org_table_html = ""
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repos</th>
                        <th>Discussions</th>
                        <th>Comments</th>
                        <th>Categories</th>
                        <th>Participants</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{org_summary['org']}</code></td>
                        <td>{org_summary['repos']}</td>
                        <td>{org_summary['discussions']}</td>
                        <td>{org_summary['comments']}</td>
                        <td>{org_summary['categories']}</td>
                        <td>{org_summary['participants']}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No discussions data available.</p>"
        
        return f"""
        <section id="discussions-analysis">
            <h2>19. Discussions Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{len(org_summaries)}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{total_discussions}</h3>
                    <p>Total Discussions</p>
                </div>
                <div class="stat-card">
                    <h3>{total_comments}</h3>
                    <p>Total Comments</p>
                </div>
                <div class="stat-card">
                    <h3>{total_participants}</h3>
                    <p>Participants</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {org_table_html}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Discussions Security Considerations</h3>
                <ul>
                    <li><strong>Community Engagement:</strong> Discussions reveal community engagement and communication patterns</li>
                    <li><strong>Information Disclosure:</strong> Discussion content may contain sensitive information</li>
                    <li><strong>Participant Analysis:</strong> Discussion participants reveal community structure</li>
                </ul>
            </div>
        </section>
        """

    def _generate_commits_section(self, commits_data: Dict[str, Any]) -> str:
        """Generate commits analysis section."""
        org_summaries = []
        total_commits = 0
        total_authors = set()
        total_additions = 0
        total_deletions = 0
        
        if commits_data:
            for org_name, org_data in commits_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "commits": summary.get("total_commits", 0),
                        "authors": summary.get("total_unique_authors", 0),
                        "additions": summary.get("total_additions", 0),
                        "deletions": summary.get("total_deletions", 0)
                    })
                    total_commits += summary.get("total_commits", 0)
                    total_additions += summary.get("total_additions", 0)
                    total_deletions += summary.get("total_deletions", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Commits</th>
                        <th>Authors</th>
                        <th>Additions</th>
                        <th>Deletions</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['commits']}}</td>
                        <td>{{org_summary['authors']}}</td>
                        <td>{{org_summary['additions']:,}}</td>
                        <td>{{org_summary['deletions']:,}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No commits data available.</p>"
        
        return f"""
        <section id="commits-analysis">
            <h2>20. Commit Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_commits:,}}</h3>
                    <p>Total Commits</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_additions:,}}</h3>
                    <p>Total Additions</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_deletions:,}}</h3>
                    <p>Total Deletions</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Commit Analysis Security Considerations</h3>
                <ul>
                    <li><strong>Code History:</strong> Commit history reveals code evolution and changes</li>
                    <li><strong>Contributor Analysis:</strong> Commit authors reveal team structure and contributors</li>
                    <li><strong>Code Patterns:</strong> Commit messages and changes reveal development patterns</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_branches_section(self, branches_data: Dict[str, Any]) -> str:
        """Generate branches analysis section."""
        org_summaries = []
        total_branches = 0
        total_protected = 0
        
        if branches_data:
            for org_name, org_data in branches_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "branches": summary.get("total_branches", 0),
                        "protected": summary.get("total_protected_branches", 0),
                        "repos_with_protection": summary.get("repos_with_protection", 0)
                    })
                    total_branches += summary.get("total_branches", 0)
                    total_protected += summary.get("total_protected_branches", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Total Branches</th>
                        <th>Protected Branches</th>
                        <th>Repos with Protection</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['branches']}}</td>
                        <td>{{org_summary['protected']}}</td>
                        <td>{{org_summary['repos_with_protection']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No branches data available.</p>"
        
        protection_rate = total_protected / total_branches * 100 if total_branches > 0 else 0
        
        return f"""
        <section id="branches-analysis">
            <h2>21. Branch Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_branches}}</h3>
                    <p>Total Branches</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_protected}}</h3>
                    <p>Protected Branches</p>
                </div>
                <div class="stat-card">
                    <h3>{{protection_rate:.1f}}%</h3>
                    <p>Protection Rate</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Branch Analysis Security Considerations</h3>
                <ul>
                    <li><strong>Branch Protection:</strong> Protected branches prevent unauthorized changes</li>
                    <li><strong>Default Branch:</strong> Default branch is the main development branch</li>
                    <li><strong>Branch Structure:</strong> Branch structure reveals development workflow</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_teams_section(self, teams_data: Dict[str, Any]) -> str:
        """Generate teams analysis section."""
        org_summaries = []
        total_teams = 0
        total_members = 0
        total_repos = 0
        
        if teams_data:
            for org_name, org_data in teams_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "teams": summary.get("total_teams", 0),
                        "members": summary.get("total_members", 0),
                        "repositories": summary.get("total_repositories", 0)
                    })
                    total_teams += summary.get("total_teams", 0)
                    total_members += summary.get("total_members", 0)
                    total_repos += summary.get("total_repositories", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Teams</th>
                        <th>Members</th>
                        <th>Repositories</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['teams']}}</td>
                        <td>{{org_summary['members']}}</td>
                        <td>{{org_summary['repositories']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No teams data available.</p>"
        
        return f"""
        <section id="teams-analysis">
            <h2>22. Team Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_teams}}</h3>
                    <p>Total Teams</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_members}}</h3>
                    <p>Total Members</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_repos}}</h3>
                    <p>Team Repositories</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Team Analysis Security Considerations</h3>
                <ul>
                    <li><strong>Access Control:</strong> Teams define access control and permissions</li>
                    <li><strong>Permission Escalation:</strong> Team permissions may grant elevated access</li>
                    <li><strong>Team Structure:</strong> Team structure reveals organizational hierarchy</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_notifications_section(self, notifications_data: Dict[str, Any]) -> str:
        """Generate notifications analysis section."""
        summary = notifications_data.get("summary", {}) if notifications_data else {}
        total = summary.get("total", 0)
        unread = summary.get("unread", 0)
        read = summary.get("read", 0)
        reasons = summary.get("reasons", {})
        types = summary.get("types", {})
        repos = summary.get("repositories", [])
        
        reasons_html = ""
        if reasons:
            reasons_html = "<ul>"
            for reason, count in sorted(reasons.items(), key=lambda x: x[1], reverse=True)[:10]:
                reasons_html += f"<li><strong>{{reason}}:</strong> {{count}}</li>"
            reasons_html += "</ul>"
        else:
            reasons_html = "<p style='color: #7f8c8d;'>No notification reasons available.</p>"
        
        types_html = ""
        if types:
            types_html = "<ul>"
            for notif_type, count in sorted(types.items(), key=lambda x: x[1], reverse=True)[:10]:
                types_html += f"<li><strong>{{notif_type}}:</strong> {{count}}</li>"
            types_html += "</ul>"
        else:
            types_html = "<p style='color: #7f8c8d;'>No notification types available.</p>"
        
        return f"""
        <section id="notifications-analysis">
            <h2>23. Notifications Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{total}}</h3>
                    <p>Total Notifications</p>
                </div>
                <div class="stat-card">
                    <h3>{{unread}}</h3>
                    <p>Unread</p>
                </div>
                <div class="stat-card">
                    <h3>{{read}}</h3>
                    <p>Read</p>
                </div>
                <div class="stat-card">
                    <h3>{{len(repos)}}</h3>
                    <p>Repositories</p>
                </div>
            </div>
            
            <h3>Notification Reasons</h3>
            {{reasons_html}}
            
            <h3>Notification Types</h3>
            {{types_html}}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Notifications Security Considerations</h3>
                <ul>
                    <li><strong>Activity Monitoring:</strong> Notifications reveal user activity and engagement</li>
                    <li><strong>Repository Access:</strong> Notification repositories indicate accessible repositories</li>
                    <li><strong>Information Disclosure:</strong> Notification content may contain sensitive information</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_webhooks_detailed_section(self, webhooks_data: Dict[str, Any]) -> str:
        """Generate detailed webhook analysis section."""
        org_summaries = []
        total_webhooks = 0
        total_active = 0
        
        if webhooks_data:
            for org_name, org_data in webhooks_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "webhooks": summary.get("total_webhooks", 0),
                        "active": summary.get("active_webhooks", 0),
                        "event_types": len(summary.get("event_types", []))
                    })
                    total_webhooks += summary.get("total_webhooks", 0)
                    total_active += summary.get("active_webhooks", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Total Webhooks</th>
                        <th>Active Webhooks</th>
                        <th>Event Types</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['webhooks']}}</td>
                        <td>{{org_summary['active']}}</td>
                        <td>{{org_summary['event_types']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No webhooks data available.</p>"
        
        active_rate = total_active / total_webhooks * 100 if total_webhooks > 0 else 0
        
        return f"""
        <section id="webhooks-detailed-analysis">
            <h2>24. Detailed Webhook Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_webhooks}}</h3>
                    <p>Total Webhooks</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_active}}</h3>
                    <p>Active Webhooks</p>
                </div>
                <div class="stat-card">
                    <h3>{{active_rate:.1f}}%</h3>
                    <p>Active Rate</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Detailed Webhook Analysis Security Considerations</h3>
                <ul>
                    <li><strong>Webhook URLs:</strong> Webhook URLs may expose internal infrastructure</li>
                    <li><strong>Delivery History:</strong> Webhook delivery history reveals webhook activity</li>
                    <li><strong>Event Types:</strong> Webhook events reveal what actions trigger notifications</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_oauth_apps_section(self, oauth_apps_data: Dict[str, Any], org_oauth_apps: Dict[str, Any]) -> str:
        """Generate OAuth apps analysis section."""
        user_apps = oauth_apps_data.get("authorized_applications", []) if oauth_apps_data else []
        total_user_apps = len(user_apps)
        scopes = set()
        
        for app in user_apps:
            for scope in app.get("scopes", []):
                scopes.add(scope)
        
        org_summaries = []
        total_org_apps = 0
        
        if org_oauth_apps:
            for org_name, org_data in org_oauth_apps.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    org_summaries.append({
                        "org": org_name,
                        "apps": org_data["summary"].get("total_apps", 0)
                    })
                    total_org_apps += org_data["summary"].get("total_apps", 0)
        
        org_table_html = ""
        if org_summaries:
            org_table_html = """
            <h3>Organization OAuth Apps</h3>
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>OAuth Apps</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['apps']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        
        return f"""
        <section id="oauth-apps-analysis">
            <h2>25. OAuth App Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{total_user_apps}}</h3>
                    <p>Authorized Apps</p>
                </div>
                <div class="stat-card">
                    <h3>{{len(scopes)}}</h3>
                    <p>Unique Scopes</p>
                </div>
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_org_apps}}</h3>
                    <p>Org OAuth Apps</p>
                </div>
            </div>
            
            {{org_table_html}}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ OAuth App Security Considerations</h3>
                <ul>
                    <li><strong>Token Access:</strong> OAuth apps have access to user tokens and scopes</li>
                    <li><strong>Permission Scope:</strong> OAuth app scopes define what the app can access</li>
                    <li><strong>Third-Party Access:</strong> Authorized apps represent third-party access to GitHub resources</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_github_apps_section(self, github_apps_data: Dict[str, Any], org_github_apps: Dict[str, Any]) -> str:
        """Generate GitHub Apps analysis section."""
        user_installations = github_apps_data.get("installations", []) if github_apps_data else []
        total_user_installations = len(user_installations)
        app_names = []
        
        for installation in user_installations:
            app_name = installation.get("app", {}).get("name", "")
            if app_name:
                app_names.append(app_name)
        
        org_summaries = []
        total_org_installations = 0
        
        if org_github_apps:
            for org_name, org_data in org_github_apps.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    org_summaries.append({
                        "org": org_name,
                        "installations": org_data["summary"].get("total_installations", 0)
                    })
                    total_org_installations += org_data["summary"].get("total_installations", 0)
        
        org_table_html = ""
        if org_summaries:
            org_table_html = """
            <h3>Organization GitHub App Installations</h3>
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Installations</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['installations']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        
        return f"""
        <section id="github-apps-analysis">
            <h2>26. GitHub App Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{total_user_installations}}</h3>
                    <p>User Installations</p>
                </div>
                <div class="stat-card">
                    <h3>{{len(set(app_names))}}</h3>
                    <p>Unique Apps</p>
                </div>
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_org_installations}}</h3>
                    <p>Org Installations</p>
                </div>
            </div>
            
            {{org_table_html}}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ GitHub App Security Considerations</h3>
                <ul>
                    <li><strong>App Permissions:</strong> GitHub Apps have specific permissions and access scopes</li>
                    <li><strong>Installation Access:</strong> App installations grant access to repositories and organizations</li>
                    <li><strong>Automated Access:</strong> GitHub Apps provide automated access to GitHub resources</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_dependencies_section(self, dependencies_data: Dict[str, Any]) -> str:
        """Generate dependencies analysis section."""
        org_summaries = []
        total_repos = 0
        total_vulnerable = 0
        repos_with_vulns = 0
        
        if dependencies_data:
            for org_name, org_data in dependencies_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "vulnerable": summary.get("total_vulnerable_dependencies", 0),
                        "repos_with_vulns": summary.get("repos_with_vulnerabilities", 0)
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    total_vulnerable += summary.get("total_vulnerable_dependencies", 0)
                    repos_with_vulns += summary.get("repos_with_vulnerabilities", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Vulnerable Dependencies</th>
                        <th>Repos with Vulnerabilities</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['vulnerable']}}</td>
                        <td>{{org_summary['repos_with_vulns']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No dependencies data available.</p>"
        
        return f"""
        <section id="dependencies-analysis">
            <h2>27. Dependency Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_repos}}</h3>
                    <p>Repositories Analyzed</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_vulnerable}}</h3>
                    <p>Vulnerable Dependencies</p>
                </div>
                <div class="stat-card">
                    <h3>{{repos_with_vulns}}</h3>
                    <p>Repos with Vulnerabilities</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Dependency Analysis Security Considerations</h3>
                <ul>
                    <li><strong>Vulnerability Exposure:</strong> Vulnerable dependencies expose applications to security risks</li>
                    <li><strong>Dependency Graph:</strong> Dependency graph reveals application dependencies and relationships</li>
                    <li><strong>License Compliance:</strong> Dependency licenses may have compliance requirements</li>
                </ul>
            </div>
        </section>
        """


    def _generate_pr_reviews_section(self, pr_reviews_data: Dict[str, Any]) -> str:
        """Generate PR reviews analysis section."""
        org_summaries = []
        total_prs = 0
        total_reviews = 0
        total_approved = 0
        total_changes_requested = 0
        
        if pr_reviews_data:
            for org_name, org_data in pr_reviews_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "prs": summary.get("total_prs", 0),
                        "reviews": summary.get("total_reviews", 0),
                        "approved": summary.get("approved", 0),
                        "changes_requested": summary.get("changes_requested", 0),
                        "reviewers": summary.get("unique_reviewers", 0)
                    })
                    total_prs += summary.get("total_prs", 0)
                    total_reviews += summary.get("total_reviews", 0)
                    total_approved += summary.get("approved", 0)
                    total_changes_requested += summary.get("changes_requested", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>PRs Analyzed</th>
                        <th>Total Reviews</th>
                        <th>Approved</th>
                        <th>Changes Requested</th>
                        <th>Reviewers</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['prs']}}</td>
                        <td>{{org_summary['reviews']}}</td>
                        <td>{{org_summary['approved']}}</td>
                        <td>{{org_summary['changes_requested']}}</td>
                        <td>{{org_summary['reviewers']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No PR reviews data available.</p>"
        
        return f"""
        <section id="pr-reviews-analysis">
            <h2>28. PR Reviews Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_prs}}</h3>
                    <p>PRs Analyzed</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_reviews}}</h3>
                    <p>Total Reviews</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_approved}}</h3>
                    <p>Approved</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ PR Reviews Security Considerations</h3>
                <ul>
                    <li><strong>Code Review Process:</strong> Reviews reveal code review processes and approval workflows</li>
                    <li><strong>Review Comments:</strong> Review comments may contain sensitive information</li>
                    <li><strong>Approval Patterns:</strong> Review approval patterns reveal code quality standards</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_repository_settings_section(self, repo_settings_data: Dict[str, Any]) -> str:
        """Generate repository settings analysis section."""
        org_summaries = []
        total_repos = 0
        private_repos = 0
        repos_with_protection = 0
        repos_with_vuln_alerts = 0
        
        if repo_settings_data:
            for org_name, org_data in repo_settings_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "private": summary.get("private_repos", 0),
                        "protected": summary.get("repos_with_branch_protection", 0),
                        "vuln_alerts": summary.get("repos_with_vulnerability_alerts", 0)
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    private_repos += summary.get("private_repos", 0)
                    repos_with_protection += summary.get("repos_with_branch_protection", 0)
                    repos_with_vuln_alerts += summary.get("repos_with_vulnerability_alerts", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Private</th>
                        <th>Branch Protection</th>
                        <th>Vulnerability Alerts</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['private']}}</td>
                        <td>{{org_summary['protected']}}</td>
                        <td>{{org_summary['vuln_alerts']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No repository settings data available.</p>"
        
        return f"""
        <section id="repository-settings-analysis">
            <h2>29. Repository Settings Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_repos}}</h3>
                    <p>Repositories</p>
                </div>
                <div class="stat-card">
                    <h3>{{private_repos}}</h3>
                    <p>Private Repos</p>
                </div>
                <div class="stat-card">
                    <h3>{{repos_with_protection}}</h3>
                    <p>With Branch Protection</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Repository Settings Security Considerations</h3>
                <ul>
                    <li><strong>Visibility Settings:</strong> Repository visibility reveals access control policies</li>
                    <li><strong>Security Features:</strong> Vulnerability alerts and dependency graph settings reveal security posture</li>
                    <li><strong>Merge Settings:</strong> Merge settings reveal code integration policies</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_organization_settings_section(self, org_settings_data: Dict[str, Any]) -> str:
        """Generate organization settings analysis section."""
        org_summaries = []
        total_orgs = 0
        orgs_with_2fa = 0
        orgs_allow_member_repos = 0
        
        if org_settings_data:
            if "organizations" in org_settings_data:
                # Multiple orgs
                for org_name, org_data in org_settings_data["organizations"].items():
                    if isinstance(org_data, dict):
                        org_summaries.append({
                            "org": org_name,
                            "has_2fa": org_data.get("security_settings", {}).get("two_factor_requirement_enabled", False),
                            "allow_member_repos": org_data.get("member_settings", {}).get("members_can_create_repositories", False),
                            "default_permission": org_data.get("member_settings", {}).get("default_repository_permission", "")
                        })
                        total_orgs += 1
                        if org_summaries[-1]["has_2fa"]:
                            orgs_with_2fa += 1
                        if org_summaries[-1]["allow_member_repos"]:
                            orgs_allow_member_repos += 1
            else:
                # Single org
                for org_name, org_data in org_settings_data.items():
                    if isinstance(org_data, dict):
                        org_summaries.append({
                            "org": org_name,
                            "has_2fa": org_data.get("security_settings", {}).get("two_factor_requirement_enabled", False),
                            "allow_member_repos": org_data.get("member_settings", {}).get("members_can_create_repositories", False),
                            "default_permission": org_data.get("member_settings", {}).get("default_repository_permission", "")
                        })
                        total_orgs += 1
                        if org_summaries[-1]["has_2fa"]:
                            orgs_with_2fa += 1
                        if org_summaries[-1]["allow_member_repos"]:
                            orgs_allow_member_repos += 1
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>2FA Required</th>
                        <th>Members Can Create Repos</th>
                        <th>Default Permission</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{'✓' if org_summary['has_2fa'] else '✗'}}</td>
                        <td>{{'✓' if org_summary['allow_member_repos'] else '✗'}}</td>
                        <td>{{org_summary['default_permission']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No organization settings data available.</p>"
        
        return f"""
        <section id="organization-settings-analysis">
            <h2>30. Organization Settings Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{total_orgs}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{orgs_with_2fa}}</h3>
                    <p>With 2FA Required</p>
                </div>
                <div class="stat-card">
                    <h3>{{orgs_allow_member_repos}}</h3>
                    <p>Allow Member Repos</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_orgs - orgs_with_2fa}}</h3>
                    <p>Without 2FA</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Organization Settings Security Considerations</h3>
                <ul>
                    <li><strong>2FA Requirements:</strong> Two-factor authentication requirements reveal security posture</li>
                    <li><strong>Member Permissions:</strong> Member permissions reveal access control policies</li>
                    <li><strong>Repository Policies:</strong> Repository creation policies reveal organizational structure</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_environment_secrets_section(self, env_secrets_data: Dict[str, Any]) -> str:
        """Generate environment secrets analysis section."""
        org_summaries = []
        total_repos = 0
        total_environments = 0
        total_secrets = 0
        total_variables = 0
        
        if env_secrets_data:
            for org_name, org_data in env_secrets_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "environments": summary.get("total_environments", 0),
                        "secrets": summary.get("total_secrets", 0),
                        "variables": summary.get("total_variables", 0)
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    total_environments += summary.get("total_environments", 0)
                    total_secrets += summary.get("total_secrets", 0)
                    total_variables += summary.get("total_variables", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Environments</th>
                        <th>Secrets</th>
                        <th>Variables</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['environments']}}</td>
                        <td>{{org_summary['secrets']}}</td>
                        <td>{{org_summary['variables']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No environment secrets data available.</p>"
        
        return f"""
        <section id="environment-secrets-analysis">
            <h2>31. Environment Secrets & Variables Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_environments}}</h3>
                    <p>Environments</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_secrets}}</h3>
                    <p>Secrets</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_variables}}</h3>
                    <p>Variables</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Environment Secrets Security Considerations</h3>
                <ul>
                    <li><strong>Secret Exposure:</strong> Environment secrets are critical security assets</li>
                    <li><strong>Access Control:</strong> Environment protection rules reveal access control policies</li>
                    <li><strong>Deployment Security:</strong> Environment settings reveal deployment security posture</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_milestones_section(self, milestones_data: Dict[str, Any]) -> str:
        """Generate milestones analysis section."""
        org_summaries = []
        total_repos = 0
        total_milestones = 0
        open_milestones = 0
        closed_milestones = 0
        
        if milestones_data:
            for org_name, org_data in milestones_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "milestones": summary.get("total_milestones", 0),
                        "open": summary.get("open_milestones", 0),
                        "closed": summary.get("closed_milestones", 0)
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    total_milestones += summary.get("total_milestones", 0)
                    open_milestones += summary.get("open_milestones", 0)
                    closed_milestones += summary.get("closed_milestones", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Total Milestones</th>
                        <th>Open</th>
                        <th>Closed</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['milestones']}}</td>
                        <td>{{org_summary['open']}}</td>
                        <td>{{org_summary['closed']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No milestones data available.</p>"
        
        return f"""
        <section id="milestones-analysis">
            <h2>32. Milestones Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_milestones}}</h3>
                    <p>Total Milestones</p>
                </div>
                <div class="stat-card">
                    <h3>{{open_milestones}}</h3>
                    <p>Open Milestones</p>
                </div>
                <div class="stat-card">
                    <h3>{{closed_milestones}}</h3>
                    <p>Closed Milestones</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Milestones Security Considerations</h3>
                <ul>
                    <li><strong>Project Planning:</strong> Milestones reveal project planning and timelines</li>
                    <li><strong>Issue Tracking:</strong> Milestone issues reveal project scope and priorities</li>
                    <li><strong>Progress Tracking:</strong> Milestone progress reveals project status</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_labels_section(self, labels_data: Dict[str, Any]) -> str:
        """Generate labels analysis section."""
        org_summaries = []
        total_repos = 0
        total_labels = 0
        unique_labels = 0
        
        if labels_data:
            for org_name, org_data in labels_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "labels": summary.get("total_labels", 0),
                        "unique": len(summary.get("unique_labels", []))
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    total_labels += summary.get("total_labels", 0)
                    unique_labels = max(unique_labels, len(summary.get("unique_labels", [])))
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Total Labels</th>
                        <th>Unique Labels</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['labels']}}</td>
                        <td>{{org_summary['unique']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No labels data available.</p>"
        
        return f"""
        <section id="labels-analysis">
            <h2>33. Labels Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_labels}}</h3>
                    <p>Total Labels</p>
                </div>
                <div class="stat-card">
                    <h3>{{unique_labels}}</h3>
                    <p>Unique Labels</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_repos}}</h3>
                    <p>Repositories</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Labels Security Considerations</h3>
                <ul>
                    <li><strong>Issue Categorization:</strong> Labels reveal issue categorization and priorities</li>
                    <li><strong>Workflow Patterns:</strong> Label usage patterns reveal workflow processes</li>
                    <li><strong>Organization Structure:</strong> Label distribution reveals organizational structure</li>
                </ul>
            </div>
        </section>
        """

    def _generate_projects_section(self, projects_data: Dict[str, Any]) -> str:
        """Generate projects analysis section."""
        org_summaries = []
        total_org_projects = 0
        total_repo_projects = 0
        
        if projects_data:
            for org_name, org_data in projects_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "org_projects": summary.get("org_projects", 0),
                        "repo_projects": summary.get("repo_projects", 0),
                        "repos_with_projects": summary.get("repos_with_projects", 0)
                    })
                    total_org_projects += summary.get("org_projects", 0)
                    total_repo_projects += summary.get("repo_projects", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Org Projects</th>
                        <th>Repo Projects</th>
                        <th>Repos with Projects</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['org_projects']}}</td>
                        <td>{{org_summary['repo_projects']}}</td>
                        <td>{{org_summary['repos_with_projects']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No projects data available.</p>"
        
        return f"""
        <section id="projects-analysis">
            <h2>34. GitHub Projects Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_org_projects}}</h3>
                    <p>Org Projects</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_repo_projects}}</h3>
                    <p>Repo Projects</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_org_projects + total_repo_projects}}</h3>
                    <p>Total Projects</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Projects Security Considerations</h3>
                <ul>
                    <li><strong>Project Management:</strong> Projects reveal project management and workflows</li>
                    <li><strong>Project Cards:</strong> Project cards may contain sensitive information</li>
                    <li><strong>Project Permissions:</strong> Project permissions reveal access control</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_reactions_section(self, reactions_data: Dict[str, Any]) -> str:
        """Generate reactions analysis section."""
        org_summaries = []
        total_reactions = 0
        total_issues = 0
        total_prs = 0
        
        if reactions_data:
            for org_name, org_data in reactions_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "reactions": summary.get("total_reactions", 0),
                        "issues": summary.get("total_issues_analyzed", 0),
                        "prs": summary.get("total_prs_analyzed", 0)
                    })
                    total_reactions += summary.get("total_reactions", 0)
                    total_issues += summary.get("total_issues_analyzed", 0)
                    total_prs += summary.get("total_prs_analyzed", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Total Reactions</th>
                        <th>Issues Analyzed</th>
                        <th>PRs Analyzed</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['reactions']}}</td>
                        <td>{{org_summary['issues']}}</td>
                        <td>{{org_summary['prs']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No reactions data available.</p>"
        
        return f"""
        <section id="reactions-analysis">
            <h2>35. Reactions Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_reactions}}</h3>
                    <p>Total Reactions</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_issues}}</h3>
                    <p>Issues Analyzed</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_prs}}</h3>
                    <p>PRs Analyzed</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Reactions Security Considerations</h3>
                <ul>
                    <li><strong>Community Engagement:</strong> Reactions reveal community engagement patterns</li>
                    <li><strong>Content Popularity:</strong> Reaction patterns reveal popular content</li>
                    <li><strong>User Activity:</strong> Reactions reveal user activity and interests</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_commit_comments_section(self, commit_comments_data: Dict[str, Any]) -> str:
        """Generate commit comments analysis section."""
        org_summaries = []
        total_comments = 0
        total_commits = 0
        commits_with_comments = 0
        
        if commit_comments_data:
            for org_name, org_data in commit_comments_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "comments": summary.get("total_comments", 0),
                        "commits": summary.get("total_commits_analyzed", 0),
                        "commits_with_comments": summary.get("commits_with_comments", 0),
                        "commenters": summary.get("unique_commenters", 0) if isinstance(summary.get("unique_commenters"), int) else len(summary.get("unique_commenters", []))
                    })
                    total_comments += summary.get("total_comments", 0)
                    total_commits += summary.get("total_commits_analyzed", 0)
                    commits_with_comments += summary.get("commits_with_comments", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Comments</th>
                        <th>Commits Analyzed</th>
                        <th>Commits with Comments</th>
                        <th>Commenters</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['comments']}}</td>
                        <td>{{org_summary['commits']}}</td>
                        <td>{{org_summary['commits_with_comments']}}</td>
                        <td>{{org_summary['commenters']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No commit comments data available.</p>"
        
        return f"""
        <section id="commit-comments-analysis">
            <h2>36. Commit Comments Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_comments}}</h3>
                    <p>Total Comments</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_commits}}</h3>
                    <p>Commits Analyzed</p>
                </div>
                <div class="stat-card">
                    <h3>{{commits_with_comments}}</h3>
                    <p>Commits with Comments</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Commit Comments Security Considerations</h3>
                <ul>
                    <li><strong>Code Review:</strong> Commit comments may contain sensitive code review information</li>
                    <li><strong>Information Disclosure:</strong> Comments may reveal implementation details</li>
                    <li><strong>Line-by-Line Comments:</strong> Detailed comments may expose code vulnerabilities</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_pr_files_section(self, pr_files_data: Dict[str, Any]) -> str:
        """Generate PR files analysis section."""
        org_summaries = []
        total_prs = 0
        total_files = 0
        total_additions = 0
        total_deletions = 0
        
        if pr_files_data:
            for org_name, org_data in pr_files_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "prs": summary.get("total_prs", 0),
                        "files": summary.get("total_files_changed", 0),
                        "additions": summary.get("total_additions", 0),
                        "deletions": summary.get("total_deletions", 0)
                    })
                    total_prs += summary.get("total_prs", 0)
                    total_files += summary.get("total_files_changed", 0)
                    total_additions += summary.get("total_additions", 0)
                    total_deletions += summary.get("total_deletions", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>PRs Analyzed</th>
                        <th>Files Changed</th>
                        <th>Additions</th>
                        <th>Deletions</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['prs']}}</td>
                        <td>{{org_summary['files']}}</td>
                        <td>{{org_summary['additions']:,}}</td>
                        <td>{{org_summary['deletions']:,}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No PR files data available.</p>"
        
        return f"""
        <section id="pr-files-analysis">
            <h2>37. PR Files Changed Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_prs}}</h3>
                    <p>PRs Analyzed</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_files}}</h3>
                    <p>Files Changed</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_additions + total_deletions:,}}</h3>
                    <p>Total Changes</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ PR Files Security Considerations</h3>
                <ul>
                    <li><strong>Code Changes:</strong> PR files reveal what code changes are being made</li>
                    <li><strong>File Patterns:</strong> File change patterns reveal development focus areas</li>
                    <li><strong>Change Statistics:</strong> Change statistics reveal code modification patterns</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_issue_events_section(self, issue_events_data: Dict[str, Any]) -> str:
        """Generate issue events analysis section."""
        org_summaries = []
        total_issues = 0
        total_events = 0
        
        if issue_events_data:
            for org_name, org_data in issue_events_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "issues": summary.get("total_issues_analyzed", 0),
                        "events": summary.get("total_events", 0),
                        "unique_actors": summary.get("unique_actors", 0) if isinstance(summary.get("unique_actors"), int) else len(summary.get("unique_actors", []))
                    })
                    total_issues += summary.get("total_issues_analyzed", 0)
                    total_events += summary.get("total_events", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Issues Analyzed</th>
                        <th>Total Events</th>
                        <th>Unique Actors</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['issues']}}</td>
                        <td>{{org_summary['events']}}</td>
                        <td>{{org_summary['unique_actors']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No issue events data available.</p>"
        
        return f"""
        <section id="issue-events-analysis">
            <h2>38. Issue Events/Timeline Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_issues}}</h3>
                    <p>Issues Analyzed</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_events}}</h3>
                    <p>Total Events</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_events / total_issues if total_issues > 0 else 0:.1f}}</h3>
                    <p>Avg Events/Issue</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Issue Events Security Considerations</h3>
                <ul>
                    <li><strong>Issue Lifecycle:</strong> Events reveal issue lifecycle and resolution patterns</li>
                    <li><strong>State Changes:</strong> State change history reveals workflow processes</li>
                    <li><strong>Event Actors:</strong> Event actors reveal who performs what actions</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_contributors_section(self, contributors_data: Dict[str, Any]) -> str:
        """Generate contributors analysis section."""
        org_summaries = []
        total_repos = 0
        total_contributors = 0
        unique_contributors = 0
        total_contributions = 0
        
        if contributors_data:
            for org_name, org_data in contributors_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "contributors": summary.get("total_contributors", 0),
                        "unique": summary.get("unique_contributors", 0) if isinstance(summary.get("unique_contributors"), int) else len(summary.get("unique_contributors", [])),
                        "contributions": summary.get("total_contributions", 0)
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    total_contributors += summary.get("total_contributors", 0)
                    unique_contributors = max(unique_contributors, summary.get("unique_contributors", 0) if isinstance(summary.get("unique_contributors"), int) else len(summary.get("unique_contributors", [])))
                    total_contributions += summary.get("total_contributions", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Contributors</th>
                        <th>Unique Contributors</th>
                        <th>Total Contributions</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['contributors']}}</td>
                        <td>{{org_summary['unique']}}</td>
                        <td>{{org_summary['contributions']:,}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No contributors data available.</p>"
        
        return f"""
        <section id="contributors-analysis">
            <h2>39. Contributors Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_contributors}}</h3>
                    <p>Total Contributors</p>
                </div>
                <div class="stat-card">
                    <h3>{{unique_contributors}}</h3>
                    <p>Unique Contributors</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_contributions:,}}</h3>
                    <p>Total Contributions</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Contributors Security Considerations</h3>
                <ul>
                    <li><strong>Access Control:</strong> Contributors reveal who has access to repositories</li>
                    <li><strong>Activity Patterns:</strong> Contributor activity patterns reveal development focus</li>
                    <li><strong>Team Structure:</strong> Contributors reveal team structure and organization</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_stargazers_watchers_section(self, stargazers_watchers_data: Dict[str, Any]) -> str:
        """Generate stargazers/watchers analysis section."""
        org_summaries = []
        total_repos = 0
        total_stargazers = 0
        total_watchers = 0
        
        if stargazers_watchers_data:
            for org_name, org_data in stargazers_watchers_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "stargazers": summary.get("total_stargazers", 0),
                        "watchers": summary.get("total_watchers", 0),
                        "unique_stargazers": summary.get("unique_stargazers", 0) if isinstance(summary.get("unique_stargazers"), int) else len(summary.get("unique_stargazers", [])),
                        "unique_watchers": summary.get("unique_watchers", 0) if isinstance(summary.get("unique_watchers"), int) else len(summary.get("unique_watchers", []))
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    total_stargazers += summary.get("total_stargazers", 0)
                    total_watchers += summary.get("total_watchers", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Stargazers</th>
                        <th>Watchers</th>
                        <th>Unique Stargazers</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['stargazers']}}</td>
                        <td>{{org_summary['watchers']}}</td>
                        <td>{{org_summary['unique_stargazers']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No stargazers/watchers data available.</p>"
        
        return f"""
        <section id="stargazers-watchers-analysis">
            <h2>40. Stargazers/Watchers Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_stargazers}}</h3>
                    <p>Total Stargazers</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_watchers}}</h3>
                    <p>Total Watchers</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_repos}}</h3>
                    <p>Repositories</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Stargazers/Watchers Security Considerations</h3>
                <ul>
                    <li><strong>Repository Popularity:</strong> Stargazers reveal repository popularity and interest</li>
                    <li><strong>User Interests:</strong> Star/watch patterns reveal user interests</li>
                    <li><strong>Network Analysis:</strong> Stargazers/watchers reveal social network connections</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_fork_network_section(self, fork_network_data: Dict[str, Any]) -> str:
        """Generate fork network analysis section."""
        org_summaries = []
        total_repos = 0
        total_forks = 0
        repos_with_forks = 0
        
        if fork_network_data:
            for org_name, org_data in fork_network_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "forks": summary.get("total_forks", 0),
                        "repos_with_forks": summary.get("repos_with_forks", 0),
                        "unique_forkers": summary.get("unique_forkers", 0) if isinstance(summary.get("unique_forkers"), int) else len(summary.get("unique_forkers", []))
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    total_forks += summary.get("total_forks", 0)
                    repos_with_forks += summary.get("repos_with_forks", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Total Forks</th>
                        <th>Repos with Forks</th>
                        <th>Unique Forkers</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['forks']}}</td>
                        <td>{{org_summary['repos_with_forks']}}</td>
                        <td>{{org_summary['unique_forkers']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No fork network data available.</p>"
        
        return f"""
        <section id="fork-network-analysis">
            <h2>41. Fork Network Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_forks}}</h3>
                    <p>Total Forks</p>
                </div>
                <div class="stat-card">
                    <h3>{{repos_with_forks}}</h3>
                    <p>Repos with Forks</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_repos}}</h3>
                    <p>Repositories Analyzed</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Fork Network Security Considerations</h3>
                <ul>
                    <li><strong>Code Distribution:</strong> Fork network reveals code distribution and forks</li>
                    <li><strong>Fork Relationships:</strong> Fork relationships reveal code sharing patterns</li>
                    <li><strong>Fork Activity:</strong> Fork activity reveals repository popularity</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_release_assets_section(self, release_assets_data: Dict[str, Any]) -> str:
        """Generate release assets analysis section."""
        org_summaries = []
        total_repos = 0
        total_releases = 0
        total_assets = 0
        total_asset_size = 0
        
        if release_assets_data:
            for org_name, org_data in release_assets_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "releases": summary.get("total_releases", 0),
                        "assets": summary.get("total_assets", 0),
                        "asset_size_mb": round(summary.get("total_asset_size", 0) / (1024 * 1024), 2)
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    total_releases += summary.get("total_releases", 0)
                    total_assets += summary.get("total_assets", 0)
                    total_asset_size += summary.get("total_asset_size", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Releases</th>
                        <th>Assets</th>
                        <th>Asset Size (MB)</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['releases']}}</td>
                        <td>{{org_summary['assets']}}</td>
                        <td>{{org_summary['asset_size_mb']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No release assets data available.</p>"
        
        total_size_mb = round(total_asset_size / (1024 * 1024), 2)
        
        return f"""
        <section id="release-assets-analysis">
            <h2>42. Release Assets Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_releases}}</h3>
                    <p>Total Releases</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_assets}}</h3>
                    <p>Total Assets</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_size_mb}} MB</h3>
                    <p>Total Asset Size</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Release Assets Security Considerations</h3>
                <ul>
                    <li><strong>Asset Content:</strong> Release assets may contain sensitive information or binaries</li>
                    <li><strong>Download Access:</strong> Asset download URLs reveal distribution mechanisms</li>
                    <li><strong>Asset Permissions:</strong> Asset permissions reveal access control policies</li>
                </ul>
            </div>
        </section>
        """

    def _generate_repository_invitations_section(self, invitations_data: Dict[str, Any]) -> str:
        """Generate repository invitations analysis section."""
        org_summaries = []
        total_repos = 0
        total_pending = 0
        repos_with_invitations = 0
        
        if invitations_data:
            for org_name, org_data in invitations_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "pending": summary.get("total_pending_invitations", 0),
                        "repos_with_invitations": summary.get("repos_with_invitations", 0)
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    total_pending += summary.get("total_pending_invitations", 0)
                    repos_with_invitations += summary.get("repos_with_invitations", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Pending Invitations</th>
                        <th>Repos with Invitations</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['pending']}}</td>
                        <td>{{org_summary['repos_with_invitations']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No invitations data available.</p>"
        
        return f"""
        <section id="repository-invitations-analysis">
            <h2>43. Repository Invitations Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_pending}}</h3>
                    <p>Pending Invitations</p>
                </div>
                <div class="stat-card">
                    <h3>{{repos_with_invitations}}</h3>
                    <p>Repos with Invitations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_repos}}</h3>
                    <p>Repositories Analyzed</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Repository Invitations Security Considerations</h3>
                <ul>
                    <li><strong>Access Attempts:</strong> Pending invitations reveal access attempts and pending access</li>
                    <li><strong>Invitation Permissions:</strong> Invitation permissions reveal what access is being granted</li>
                    <li><strong>Access Control:</strong> Invitations reveal access control and collaboration patterns</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_repository_transfers_section(self, transfers_data: Dict[str, Any]) -> str:
        """Generate repository transfers analysis section."""
        org_summaries = []
        total_repos = 0
        repos_possibly_transferred = 0
        
        if transfers_data:
            for org_name, org_data in transfers_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "possibly_transferred": summary.get("repos_possibly_transferred", 0)
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    repos_possibly_transferred += summary.get("repos_possibly_transferred", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Possibly Transferred</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['possibly_transferred']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No transfer data available.</p>"
        
        return f"""
        <section id="repository-transfers-analysis">
            <h2>44. Repository Transfer History Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_repos}}</h3>
                    <p>Repositories Analyzed</p>
                </div>
                <div class="stat-card">
                    <h3>{{repos_possibly_transferred}}</h3>
                    <p>Possibly Transferred</p>
                </div>
                <div class="stat-card">
                    <h3>{{repos_possibly_transferred / total_repos * 100 if total_repos > 0 else 0:.1f}}%</h3>
                    <p>Transfer Rate</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Repository Transfers Security Considerations</h3>
                <ul>
                    <li><strong>Ownership Changes:</strong> Repository transfers reveal ownership changes</li>
                    <li><strong>Transfer History:</strong> Transfer history reveals repository ownership evolution</li>
                    <li><strong>Access Control:</strong> Transfers may indicate access control changes</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_workflow_run_logs_section(self, workflow_logs_data: Dict[str, Any]) -> str:
        """Generate workflow run logs analysis section."""
        org_summaries = []
        total_repos = 0
        total_runs = 0
        runs_with_logs = 0
        successful_runs = 0
        failed_runs = 0
        
        if workflow_logs_data:
            for org_name, org_data in workflow_logs_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "runs": summary.get("total_runs", 0),
                        "runs_with_logs": summary.get("runs_with_logs", 0),
                        "successful": summary.get("successful_runs", 0),
                        "failed": summary.get("failed_runs", 0)
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    total_runs += summary.get("total_runs", 0)
                    runs_with_logs += summary.get("runs_with_logs", 0)
                    successful_runs += summary.get("successful_runs", 0)
                    failed_runs += summary.get("failed_runs", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Total Runs</th>
                        <th>Runs with Logs</th>
                        <th>Successful</th>
                        <th>Failed</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['runs']}}</td>
                        <td>{{org_summary['runs_with_logs']}}</td>
                        <td>{{org_summary['successful']}}</td>
                        <td>{{org_summary['failed']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No workflow logs data available.</p>"
        
        return f"""
        <section id="workflow-run-logs-analysis">
            <h2>45. Workflow Run Logs Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_runs}}</h3>
                    <p>Total Runs</p>
                </div>
                <div class="stat-card">
                    <h3>{{runs_with_logs}}</h3>
                    <p>Runs with Logs</p>
                </div>
                <div class="stat-card">
                    <h3>{{successful_runs}}</h3>
                    <p>Successful Runs</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Workflow Run Logs Security Considerations</h3>
                <ul>
                    <li><strong>Log Content:</strong> Workflow logs may contain sensitive information</li>
                    <li><strong>Execution Details:</strong> Logs reveal workflow execution details and commands</li>
                    <li><strong>Secret Exposure:</strong> Logs may expose secrets or credentials</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_artifact_details_section(self, artifacts_data: Dict[str, Any]) -> str:
        """Generate artifact details analysis section."""
        org_summaries = []
        total_repos = 0
        total_artifacts = 0
        total_size = 0
        repos_with_artifacts = 0
        
        if artifacts_data:
            for org_name, org_data in artifacts_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "artifacts": summary.get("total_artifacts", 0),
                        "size_mb": round(summary.get("total_size", 0) / (1024 * 1024), 2),
                        "repos_with_artifacts": summary.get("repos_with_artifacts", 0)
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    total_artifacts += summary.get("total_artifacts", 0)
                    total_size += summary.get("total_size", 0)
                    repos_with_artifacts += summary.get("repos_with_artifacts", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Artifacts</th>
                        <th>Size (MB)</th>
                        <th>Repos with Artifacts</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['artifacts']}}</td>
                        <td>{{org_summary['size_mb']}}</td>
                        <td>{{org_summary['repos_with_artifacts']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No artifact details data available.</p>"
        
        total_size_mb = round(total_size / (1024 * 1024), 2)
        
        return f"""
        <section id="artifact-details-analysis">
            <h2>46. Artifact Details Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_artifacts}}</h3>
                    <p>Total Artifacts</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_size_mb}} MB</h3>
                    <p>Total Size</p>
                </div>
                <div class="stat-card">
                    <h3>{{repos_with_artifacts}}</h3>
                    <p>Repos with Artifacts</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Artifact Details Security Considerations</h3>
                <ul>
                    <li><strong>Build Outputs:</strong> Artifacts may contain sensitive build outputs</li>
                    <li><strong>Download Access:</strong> Artifact download URLs reveal distribution mechanisms</li>
                    <li><strong>Artifact Content:</strong> Artifacts may contain sensitive information or binaries</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_secret_scanning_alerts_section(self, alerts_data: Dict[str, Any]) -> str:
        """Generate secret scanning alerts analysis section."""
        org_summaries = []
        total_repos = 0
        total_alerts = 0
        open_alerts = 0
        resolved_alerts = 0
        
        if alerts_data:
            for org_name, org_data in alerts_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "alerts": summary.get("total_alerts", 0),
                        "open": summary.get("open_alerts", 0),
                        "resolved": summary.get("resolved_alerts", 0),
                        "repos_with_alerts": summary.get("repos_with_alerts", 0)
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    total_alerts += summary.get("total_alerts", 0)
                    open_alerts += summary.get("open_alerts", 0)
                    resolved_alerts += summary.get("resolved_alerts", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Total Alerts</th>
                        <th>Open Alerts</th>
                        <th>Resolved Alerts</th>
                        <th>Repos with Alerts</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['alerts']}}</td>
                        <td>{{org_summary['open']}}</td>
                        <td>{{org_summary['resolved']}}</td>
                        <td>{{org_summary['repos_with_alerts']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No secret scanning alerts data available.</p>"
        
        return f"""
        <section id="secret-scanning-alerts-analysis">
            <h2>47. Secret Scanning Alerts Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_alerts}}</h3>
                    <p>Total Alerts</p>
                </div>
                <div class="stat-card">
                    <h3>{{open_alerts}}</h3>
                    <p>Open Alerts</p>
                </div>
                <div class="stat-card">
                    <h3>{{resolved_alerts}}</h3>
                    <p>Resolved Alerts</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Secret Scanning Alerts Security Considerations</h3>
                <ul>
                    <li><strong>Secret Exposure:</strong> Secret scanning alerts reveal exposed secrets in code</li>
                    <li><strong>Remediation Status:</strong> Alert status reveals security remediation efforts</li>
                    <li><strong>Secret Types:</strong> Secret types reveal what kinds of secrets are exposed</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_code_scanning_alerts_section(self, alerts_data: Dict[str, Any]) -> str:
        """Generate code scanning alerts analysis section."""
        org_summaries = []
        total_repos = 0
        total_alerts = 0
        open_alerts = 0
        dismissed_alerts = 0
        
        if alerts_data:
            for org_name, org_data in alerts_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "alerts": summary.get("total_alerts", 0),
                        "open": summary.get("open_alerts", 0),
                        "dismissed": summary.get("dismissed_alerts", 0),
                        "repos_with_alerts": summary.get("repos_with_alerts", 0)
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    total_alerts += summary.get("total_alerts", 0)
                    open_alerts += summary.get("open_alerts", 0)
                    dismissed_alerts += summary.get("dismissed_alerts", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Total Alerts</th>
                        <th>Open Alerts</th>
                        <th>Dismissed Alerts</th>
                        <th>Repos with Alerts</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['alerts']}}</td>
                        <td>{{org_summary['open']}}</td>
                        <td>{{org_summary['dismissed']}}</td>
                        <td>{{org_summary['repos_with_alerts']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No code scanning alerts data available.</p>"
        
        return f"""
        <section id="code-scanning-alerts-analysis">
            <h2>48. Code Scanning Alerts Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_alerts}}</h3>
                    <p>Total Alerts</p>
                </div>
                <div class="stat-card">
                    <h3>{{open_alerts}}</h3>
                    <p>Open Alerts</p>
                </div>
                <div class="stat-card">
                    <h3>{{dismissed_alerts}}</h3>
                    <p>Dismissed Alerts</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Code Scanning Alerts Security Considerations</h3>
                <ul>
                    <li><strong>Code Vulnerabilities:</strong> Code scanning alerts reveal code vulnerabilities and security issues</li>
                    <li><strong>Alert Severity:</strong> Alert severity reveals criticality of security issues</li>
                    <li><strong>Remediation Status:</strong> Alert status reveals security remediation efforts</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_repository_topics_section(self, topics_data: Dict[str, Any]) -> str:
        """Generate repository topics analysis section."""
        org_summaries = []
        total_repos = 0
        unique_topics = 0
        repos_with_topics = 0
        
        if topics_data:
            for org_name, org_data in topics_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "unique_topics": len(summary.get("unique_topics", [])),
                        "repos_with_topics": summary.get("repos_with_topics", 0),
                        "top_topics": list(summary.get("topic_usage", {}).items())[:5] if summary.get("topic_usage") else []
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    unique_topics = max(unique_topics, len(summary.get("unique_topics", [])))
                    repos_with_topics += summary.get("repos_with_topics", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Unique Topics</th>
                        <th>Repos with Topics</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['unique_topics']}}</td>
                        <td>{{org_summary['repos_with_topics']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No repository topics data available.</p>"
        
        return f"""
        <section id="repository-topics-analysis">
            <h2>49. Repository Topics Deep Dive</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{unique_topics}}</h3>
                    <p>Unique Topics</p>
                </div>
                <div class="stat-card">
                    <h3>{{repos_with_topics}}</h3>
                    <p>Repos with Topics</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_repos}}</h3>
                    <p>Repositories Analyzed</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Repository Topics Security Considerations</h3>
                <ul>
                    <li><strong>Repository Categorization:</strong> Topics reveal repository categorization and purpose</li>
                    <li><strong>Topic Usage:</strong> Topic usage patterns reveal organizational structure</li>
                    <li><strong>Topic Distribution:</strong> Topic distribution reveals repository focus areas</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_repository_languages_section(self, languages_data: Dict[str, Any]) -> str:
        """Generate repository languages analysis section."""
        org_summaries = []
        total_repos = 0
        unique_languages = 0
        
        if languages_data:
            for org_name, org_data in languages_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "unique_languages": len(summary.get("unique_languages", [])),
                        "top_languages": sorted(summary.get("total_bytes_by_language", {}).items(), key=lambda x: x[1], reverse=True)[:5] if summary.get("total_bytes_by_language") else []
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    unique_languages = max(unique_languages, len(summary.get("unique_languages", [])))
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>Unique Languages</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['unique_languages']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No repository languages data available.</p>"
        
        return f"""
        <section id="repository-languages-analysis">
            <h2>50. Repository Languages Breakdown</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{unique_languages}}</h3>
                    <p>Unique Languages</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_repos}}</h3>
                    <p>Repositories Analyzed</p>
                </div>
                <div class="stat-card">
                    <h3>-</h3>
                    <p>-</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Repository Languages Security Considerations</h3>
                <ul>
                    <li><strong>Technology Stack:</strong> Languages reveal technology stack and dependencies</li>
                    <li><strong>Language Distribution:</strong> Language distribution reveals development focus</li>
                    <li><strong>Code Base Analysis:</strong> Language breakdown reveals code base composition</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_enterprise_settings_section(self, enterprise_data: Dict[str, Any]) -> str:
        """Generate enterprise settings analysis section."""
        settings_accessible = enterprise_data.get("summary", {}).get("settings_accessible", False) if enterprise_data else False
        enterprise_info = enterprise_data.get("enterprise_info", {}) if enterprise_data else {}
        billing = enterprise_data.get("billing", {}) if enterprise_data else {}
        
        info_html = ""
        if enterprise_info:
            info_html = f"""
            <h3>Enterprise Information</h3>
            <ul>
                <li><strong>Name:</strong> {{enterprise_info.get('name', 'N/A')}}</li>
                <li><strong>Slug:</strong> {{enterprise_info.get('slug', 'N/A')}}</li>
                <li><strong>Description:</strong> {{enterprise_info.get('description', 'N/A')[:200]}}</li>
                <li><strong>Created:</strong> {{enterprise_info.get('created_at', 'N/A')}}</li>
            </ul>
            """
        else:
            info_html = "<p style='color: #7f8c8d;'>No enterprise information available.</p>"
        
        billing_html = ""
        if billing and billing.get("accessible", True):
            billing_html = f"""
            <h3>Billing Information</h3>
            <ul>
                <li><strong>Plan:</strong> {{billing.get('plan', 'N/A')}}</li>
            </ul>
            """
        else:
            billing_html = "<p style='color: #7f8c8d;'>Billing information not accessible.</p>"
        
        return f"""
        <section id="enterprise-settings-analysis">
            <h2>51. Enterprise Settings Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{'✓' if settings_accessible else '✗'}}</h3>
                    <p>Settings Accessible</p>
                </div>
                <div class="stat-card">
                    <h3>{{'✓' if billing.get('accessible', False) else '✗'}}</h3>
                    <p>Billing Accessible</p>
                </div>
                <div class="stat-card">
                    <h3>-</h3>
                    <p>-</p>
                </div>
                <div class="stat-card">
                    <h3>-</h3>
                    <p>-</p>
                </div>
            </div>
            
            {{info_html}}
            {{billing_html}}
            
            <div class="alert alert-high">
                <h3 style="margin-top: 0;">⚠️ Enterprise Settings Security Considerations</h3>
                <ul>
                    <li><strong>Enterprise Policies:</strong> Enterprise settings reveal organization-wide policies</li>
                    <li><strong>Billing Information:</strong> Billing information reveals enterprise scale and usage</li>
                    <li><strong>Enterprise Access:</strong> Enterprise settings reveal enterprise-level access control</li>
                </ul>
            </div>
        </section>
        """
    
    def _generate_repository_statistics_section(self, statistics_data: Dict[str, Any]) -> str:
        """Generate repository statistics analysis section."""
        org_summaries = []
        total_repos = 0
        repos_with_stats = 0
        total_stargazers = 0
        total_forks = 0
        
        if statistics_data:
            for org_name, org_data in statistics_data.items():
                if isinstance(org_data, dict) and "summary" in org_data:
                    summary = org_data["summary"]
                    org_summaries.append({
                        "org": org_name,
                        "repos": summary.get("total_repos_analyzed", 0),
                        "repos_with_stats": summary.get("repos_with_stats", 0),
                        "stargazers": summary.get("total_stargazers", 0),
                        "forks": summary.get("total_forks", 0),
                        "watchers": summary.get("total_watchers", 0)
                    })
                    total_repos += summary.get("total_repos_analyzed", 0)
                    repos_with_stats += summary.get("repos_with_stats", 0)
                    total_stargazers += summary.get("total_stargazers", 0)
                    total_forks += summary.get("total_forks", 0)
        
        if org_summaries:
            org_table_html = """
            <table>
                <thead>
                    <tr>
                        <th>Organization</th>
                        <th>Repositories</th>
                        <th>With Stats</th>
                        <th>Stargazers</th>
                        <th>Forks</th>
                    </tr>
                </thead>
                <tbody>
            """
            for org_summary in org_summaries:
                org_table_html += f"""
                    <tr>
                        <td><code>{{org_summary['org']}}</code></td>
                        <td>{{org_summary['repos']}}</td>
                        <td>{{org_summary['repos_with_stats']}}</td>
                        <td>{{org_summary['stargazers']}}</td>
                        <td>{{org_summary['forks']}}</td>
                    </tr>
                """
            org_table_html += """
                </tbody>
            </table>
            """
        else:
            org_table_html = "<p style='color: #7f8c8d;'>No repository statistics data available.</p>"
        
        return f"""
        <section id="repository-statistics-analysis">
            <h2>52. Repository Statistics Analysis</h2>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>{{len(org_summaries)}}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card">
                    <h3>{{repos_with_stats}}</h3>
                    <p>Repos with Stats</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_stargazers}}</h3>
                    <p>Total Stargazers</p>
                </div>
                <div class="stat-card">
                    <h3>{{total_forks}}</h3>
                    <p>Total Forks</p>
                </div>
            </div>
            
            <h3>Organization Summary</h3>
            {{org_table_html}}
            
            <div class="alert alert-medium">
                <h3 style="margin-top: 0;">ℹ️ Repository Statistics Security Considerations</h3>
                <ul>
                    <li><strong>Activity Patterns:</strong> Statistics reveal repository activity and engagement patterns</li>
                    <li><strong>Engagement Metrics:</strong> Engagement metrics reveal repository popularity and usage</li>
                    <li><strong>Code Frequency:</strong> Code frequency reveals development activity patterns</li>
                </ul>
            </div>
        </section>
        """
