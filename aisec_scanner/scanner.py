#!/usr/bin/env python3
"""
AISec-Scanner - AI Security & Supply Chain Vulnerability Scanner
Author: Amir Hossein Nourzadeh
"""

import os
import json
import argparse
from datetime import datetime
from typing import List, Dict

from .rules.prompt_injection import check_prompt_injection
from .rules.dependency_check import check_dependencies
from .rules.model_analysis import analyze_model_file
from .rules.secret_detection import detect_secrets
from .reporters.html_reporter import generate_html_report
from .reporters.json_reporter import generate_json_report


class AISecScanner:
    """اصلی‌ترین کلاس اسکنر"""
    
    def __init__(self, target_path: str, verbose: bool = False):
        self.target_path = target_path
        self.verbose = verbose
        self.results = []
        self.scan_time = datetime.now().isoformat()
        
    def scan(self) -> List[Dict]:
        """اجرای تمام بررسی‌ها"""
        print(f"\n{'='*60}")
        print(f"🛡️  AISec-Scanner - اسکن امنیت هوش مصنوعی")
        print(f"{'='*60}")
        print(f"📂 مسیر هدف: {self.target_path}")
        print(f"⏱️  شروع: {self.scan_time}")
        print(f"{'='*60}\n")
        
        # ۱. بررسی تزریق پرامپت
        print("🔍 مرحله ۱: بررسی آسیب‌پذیری‌های تزریق پرامپت...")
        prompt_results = check_prompt_injection(self.target_path)
        self.results.extend(prompt_results)
        print(f"   ✅ {len(prompt_results)} مورد پیدا شد")
        
        # ۲. بررسی کتابخانه‌ها
        print("🔍 مرحله ۲: بررسی امنیت کتابخانه‌ها و وابستگی‌ها...")
        dep_results = check_dependencies(self.target_path)
        self.results.extend(dep_results)
        print(f"   ✅ {len(dep_results)} مورد پیدا شد")
        
        # ۳. تحلیل فایل‌های مدل
        print("🔍 مرحله ۳: تحلیل فایل‌های مدل (PT, H5, ONNX)...")
        model_results = analyze_model_file(self.target_path)
        self.results.extend(model_results)
        print(f"   ✅ {len(model_results)} مورد پیدا شد")
        
        # ۴. تشخیص کلیدهای API و رمزها
        print("🔍 مرحله ۴: جستجوی کلیدهای API و اطلاعات حساس...")
        secret_results = detect_secrets(self.target_path)
        self.results.extend(secret_results)
        print(f"   ✅ {len(secret_results)} مورد پیدا شد")
        
        print(f"\n{'='*60}")
        print(f"✅ اسکن کامل شد! {len(self.results)} آسیب‌پذیری پیدا شد.")
        print(f"{'='*60}\n")
        
        return self.results
    
    def generate_report(self, format: str = "html", output_file: str = "report.html"):
        """تولید گزارش"""
        if format == "html":
            html = generate_html_report(self.results, self.target_path, self.scan_time)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"📊 گزارش HTML در {output_file} ذخیره شد.")
        
        elif format == "json":
            json_data = generate_json_report(self.results, self.target_path, self.scan_time)
            with open(output_file, "w") as f:
                json.dump(json_data, f, indent=2)
            print(f"📊 گزارش JSON در {output_file} ذخیره شد.")
        
        else:
            print("❌ فرمت گزارش پشتیبانی نمی‌شود.")


def main():
    parser = argparse.ArgumentParser(
        description="AISec-Scanner - ابزار اسکن امنیت هوش مصنوعی",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "target",
        help="مسیر پروژه (پوشه یا فایل)"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["html", "json"],
        default="html",
        help="فرمت خروجی گزارش (پیش‌فرض: html)"
    )
    parser.add_argument(
        "-o", "--output",
        default="report.html",
        help="نام فایل خروجی"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="نمایش جزئیات بیشتر"
    )
    
    args = parser.parse_args()
    
    if not os.path.exists(args.target):
        print(f"❌ مسیر '{args.target}' وجود ندارد!")
        return
    
    scanner = AISecScanner(args.target, args.verbose)
    scanner.scan()
    scanner.generate_report(args.format, args.output)


if __name__ == "__main__":
    main()
