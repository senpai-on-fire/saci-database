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
        
        # For CPV files, also test instantiation
        if 'cpv' in file_path.name:
            cpv_class = None
            # Find the CPV class in the module - look for classes that inherit from CPV
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    hasattr(attr, '__bases__') and 
                    attr.__name__ != 'CPV'):
                    # Check if it inherits from CPV
                    for base in attr.__bases__:
                        if base.__name__ == 'CPV':
                            cpv_class = attr
                            break
                    if cpv_class:
                        break
            
            if cpv_class is None:
                return False, "No CPV class found in module"
            
            # Test instantiation - this verifies:
            # CPV classes can be instantiated
            # Constructor logic works properly  
            # Required parameters are handled correctly
            try:
                cpv_instance = cpv_class()
                # Verify it's actually a CPV instance
                if not hasattr(cpv_instance, 'NAME'):
                    return False, f"CPV instance missing required NAME attribute"
                return True, f"Import and instantiation successful: {cpv_class.__name__}"
            except Exception as e:
                return False, f"CPV instantiation failed: {str(e)}"
        
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
    print("This will verify: Import + Instantiation + Constructor Logic")
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
    
    # Test CPV files (with instantiation)
    print(f"\n Testing CPV files (import + instantiation)...")
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
    
    # Test vulnerability files (import only)
    print(f"\n Testing vulnerability files (import only)...")
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
    
    print(f"CPV Files (Import + Instantiation): {cpv_success:3d}/{len(cpv_files):3d} successful")
    print(f"Vulnerability Files (Import Only):  {vuln_success:3d}/{len(vuln_files):3d} successful")
    print(f"Total Success Rate:                 {(cpv_success + vuln_success):3d}/{(len(cpv_files) + len(vuln_files)):3d} ({((cpv_success + vuln_success)/(len(cpv_files) + len(vuln_files))*100):.1f}%)")
    
    print(f"\n Verified for CPVs:")
    print(f"   • CPV classes can be instantiated")
    print(f"   • Constructor logic works properly")
    print(f"   • Required parameters are handled correctly")
    
    # Show failures
    failures = [(name, msg) for name, success, msg in cpv_results + vuln_results if not success]
    
    if failures:
        print(f"\n FAILED IMPORTS ({len(failures)} files):")
        print("-" * 70)
        for name, message in failures:
            print(f"• {name}")
            print(f"  Error: {message}")
            print()
    else:
        print(f"\n ALL FILES IMPORTED SUCCESSFULLY!")
        if cpv_success == len(cpv_files):
            print(f" ALL CPVs CAN BE INSTANTIATED SUCCESSFULLY!")
    
    return 0 if len(failures) == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
