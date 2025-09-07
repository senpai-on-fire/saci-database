#!/usr/bin/env python3.11

"""
Local CPV Verification Script that verifies CPVs in the current saci-database directory
"""

import os
import sys
import importlib.util
from pathlib import Path

def add_saci_to_path():
    current_dir = Path(__file__).parent.absolute()
    saci_dir = current_dir.parent / "SACI"
    
    if saci_dir.exists():
        sys.path.insert(0, str(saci_dir))
        print(f"✅ Added SACI directory to Python path: {saci_dir}")
        return True
    else:
        print(f"❌ SACI directory not found at: {saci_dir}")
        return False

def test_import_from_file(file_path):
    try:
        # Get the module name from the file path
        relative_path = file_path.relative_to(Path(__file__).parent)
        module_name = str(relative_path).replace('/', '.').replace('.py', '')
        
        # Try to import the module
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None:
            return False, "Could not create module spec"
            
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        return True, "Import successful"
        
    except Exception as e:
        return False, str(e)

def find_cpv_files():
    cpv_files = []
    cpvs_dir = Path(__file__).parent / "saci_db" / "cpvs"
    
    if cpvs_dir.exists():
        for file_path in cpvs_dir.glob("cpv*.py"):
            if file_path.name != "__init__.py":
                cpv_files.append(file_path)
    
    return sorted(cpv_files)

def find_vuln_files():
    vuln_files = []
    vulns_dir = Path(__file__).parent / "saci_db" / "vulns"
    
    if vulns_dir.exists():
        for file_path in vulns_dir.glob("*_vuln.py"):
            if file_path.name != "__init__.py":
                vuln_files.append(file_path)
    
    return sorted(vuln_files)

def main():
    print(" Starting Local CPV Verification")
    print("Testing CPVs in the current saci-database directory")
    print("=" * 70)
    
    # Add SACI to path
    if not add_saci_to_path():
        print("❌ Cannot proceed without SACI in path")
        return 1
    
    # Find all CPV and vulnerability files
    cpv_files = find_cpv_files()
    vuln_files = find_vuln_files()
    
    print(f"\n Found {len(cpv_files)} CPV files")
    print(f" Found {len(vuln_files)} vulnerability files")
    
    # Test CPV files
    print(f"\n Testing CPV files...")
    cpv_results = []
    
    for i, cpv_file in enumerate(cpv_files, 1):
        print(f"[{i:3d}/{len(cpv_files)}] Testing {cpv_file.name}...", end=" ")
        success, message = test_import_from_file(cpv_file)
        
        if success:
            print("✅")
            cpv_results.append((cpv_file.name, True, message))
        else:
            print("❌")
            cpv_results.append((cpv_file.name, False, message))
    
    # Test vulnerability files
    print(f"\n Testing vulnerability files...")
    vuln_results = []
    
    for i, vuln_file in enumerate(vuln_files, 1):
        print(f"[{i:3d}/{len(vuln_files)}] Testing {vuln_file.name}...", end=" ")
        success, message = test_import_from_file(vuln_file)
        
        if success:
            print("✅")
            vuln_results.append((vuln_file.name, True, message))
        else:
            print("❌")
            vuln_results.append((vuln_file.name, False, message))
    
    # Summary
    print(f"\n VERIFICATION SUMMARY")
    print("=" * 70)
    
    cpv_success = sum(1 for _, success, _ in cpv_results if success)
    vuln_success = sum(1 for _, success, _ in vuln_results if success)
    
    print(f"CPV Files:          {cpv_success:3d}/{len(cpv_files):3d} successful")
    print(f"Vulnerability Files: {vuln_success:3d}/{len(vuln_files):3d} successful")
    print(f"Total Success Rate:  {(cpv_success + vuln_success):3d}/{(len(cpv_files) + len(vuln_files)):3d} ({((cpv_success + vuln_success)/(len(cpv_files) + len(vuln_files))*100):.1f}%)")
    
    # Show failures
    failures = [(name, msg) for name, success, msg in cpv_results + vuln_results if not success]
    
    if failures:
        print(f"\n❌ FAILED IMPORTS ({len(failures)} files):")
        print("-" * 70)
        for name, message in failures:
            print(f"• {name}")
            print(f"  Error: {message}")
            print()
    else:
        print(f"\n ALL FILES IMPORTED SUCCESSFULLY!")
    
    return 0 if len(failures) == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
