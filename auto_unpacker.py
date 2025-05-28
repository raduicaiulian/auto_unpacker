import os
import subprocess
import pefile
import magic
import argparse
import json
from pathlib import Path
from typing import Tuple, List, Dict, Optional

# Configuration for unpackers (add more as needed)
UNPACKERS = {
    'UPX': {
        'detection': [b'UPX!', b'UPX0', b'UPX1'],
        'command': ['upx', '-d', '-o', '{output}', '{input}'],
        'install': 'apt-get install upx-ucl'
    },
    'FSG': {
        'detection': [b'FSG!'],
        'command': ['unfsg', '{input}', '{output}'],
        'install': 'Please obtain unFSG from relevant sources'
    },
    'ASPack': {
        'detection': [b'ASPack'],
        'command': ['aspackdie', '{input}', '{output}'],
        'install': 'Please obtain ASPackDie from relevant sources'
    },
    # Add more unpackers here
}

class DieWrapper:
    """Wrapper for Detect It Easy (DIE) functionality"""
    
    def __init__(self, die_path: str = 'die'):
        """
        Initialize DIE wrapper
        :param die_path: Path to DIE executable or command if in PATH
        """
        self.die_path = die_path
        
    def is_available(self) -> bool:
        """Check if DIE is available on the system"""
        try:
            # print("self.die_path=",self.die_path)
            # breakpoint()
            result = subprocess.run([self.die_path, '--version'], 
                                   capture_output=True, 
                                   text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
            
    def analyze_file(self, file_path: str) -> Optional[Dict]:
        """
        Analyze a file with DIE and return the results as a dictionary
        :param file_path: Path to the file to analyze
        :return: Dictionary with analysis results or None if analysis failed
        """
        try:
            cmd = [self.die_path, '-j', file_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return None
                
            return json.loads(result.stdout)
        except (subprocess.SubprocessError, json.JSONDecodeError):
            return None
            
    def detect_packer(self, file_path: str) -> Tuple[Optional[str], Optional[Dict]]:
        """
        Detect packer using DIE
        :param file_path: Path to the file to analyze
        :return: Tuple of (packer_name, full_die_results) or (None, None) if detection failed
        """
        die_results = self.analyze_file(file_path)
        if not die_results:
            return None, None
            
        # Look for packer information in DIE results
        for detector in die_results.get('detects', []):
            if detector['type'].lower() == 'packer':
                return detector['name'], die_results
                
        return None, die_results

def is_packed(file_path: str, die_wrapper: Optional[DieWrapper] = None) -> Tuple[bool, Optional[str], Optional[Dict]]:
    """Check if a file is packed using various heuristics and DIE if available"""
    packer_name = None
    die_results = None
    
    # First try DIE if available
    if die_wrapper and die_wrapper.is_available():
        packer_name, die_results = die_wrapper.detect_packer(file_path)
        if packer_name:
            return True, packer_name, die_results
    
    # Fall back to manual detection if DIE not available or didn't find anything
    try:
        pe = pefile.PE(file_path)
        
        # Check for few sections with unusual characteristics
        if len(pe.sections) < 3:
            return True, "Unknown (Few sections)", die_results
            
        # Check section names for packer indicators
        packed_section_names = ['UPX', 'FSG', '.packed', '.aspack', 'y0da', 'pebundle', 'kkrunchy']
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            if any(packed_name.lower() in section_name.lower() for packed_name in packed_section_names):
                return True, f"Section: {section_name}", die_results
                
        # Check for common packer signatures in the binary
        with open(file_path, 'rb') as f:
            content = f.read()
            for packer, data in UNPACKERS.items():
                for signature in data.get('detection', []):
                    if signature in content:
                        return True, packer, die_results
                        
        # Check entry point characteristics
        if pe.OPTIONAL_HEADER.AddressOfEntryPoint < pe.OPTIONAL_HEADER.BaseOfCode:
            return True, "Unknown (Suspicious entry point)", die_results
            
    except Exception as e:
        # If PE parsing fails, it might be packed or not a PE file
        return True, f"Unknown (PE parsing failed: {str(e)})", die_results
        
    return False, None, die_results

def attempt_unpack(file_path: str, packer: str) -> Tuple[bool, str]:
    """Attempt to unpack a file using the specified packer"""
    try:
        output_path = f"{file_path}.unpacked"
        
        if packer not in UNPACKERS:
            return False, f"No unpacker configured for {packer}"
            
        cmd = [part.format(input=file_path, output=output_path) 
              for part in UNPACKERS[packer]['command']]
              
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0 and os.path.exists(output_path):
            return True, output_path
        else:
            return False, result.stderr or "Unknown unpacking error"
            
    except Exception as e:
        return False, str(e)

def analyze_directory(directory_path: str, die_wrapper: Optional[DieWrapper] = None) -> Tuple[List[Tuple], int, int]:
    """Analyze all files in a directory for packing and attempt to unpack"""
    results = []
    total_files = 0
    unpacked_files = 0
    
    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            total_files += 1
            
            print(f"\nAnalyzing {file_path}...")
            
            # Skip previously unpacked files
            if file_path.endswith('.unpacked'):
                continue
                
            # Get file type
            try:
                file_type = magic.from_file(file_path)
            except:
                file_type = "Unknown"
            
            # Check if packed
            packed, packer_name, die_results = is_packed(file_path, die_wrapper)
            
            if packed:
                print(f"Packed file detected: {packer_name}")
                
                if packer_name and packer_name in UNPACKERS:
                    # Attempt to unpack
                    success, message = attempt_unpack(file_path, packer_name)
                    if success:
                        print(f"Successfully unpacked to {message}")
                        unpacked_files += 1
                        results.append((file_path, file_type, packer_name, "Unpacked", message, die_results))
                    else:
                        print(f"Failed to unpack: {message}")
                        results.append((file_path, file_type, packer_name, "Failed", message, die_results))
                else:
                    print("Packed but no suitable unpacker configured or identified")
                    results.append((file_path, file_type, packer_name or "Unknown", "No unpacker", "", die_results))
            else:
                print("Not packed")
                results.append((file_path, file_type, "None", "Not packed", "", die_results))
    
    return results, total_files, unpacked_files

def generate_report(results: List[Tuple], output_file: Optional[str] = None) -> str:
    """Generate a detailed report of the analysis results"""
    report = []
    
    # Summary section
    packed_files = [r for r in results if r[2] != 'None']
    unpacked_success = [r for r in results if r[3] == 'Unpacked']
    
    report.append("=== Malware Unpacking Report ===")
    report.append(f"\nTotal files processed: {len(results)}")
    report.append(f"Packed files detected: {len(packed_files)}")
    report.append(f"Successfully unpacked: {len(unpacked_success)}")
    
    # Detailed findings
    report.append("\n=== Detailed Findings ===")
    for file_path, file_type, packer, status, details, die_results in results:
        report.append(f"\nFile: {file_path}")
        report.append(f"Type: {file_type}")
        report.append(f"Packer: {packer}")
        report.append(f"Status: {status}")
        if details:
            report.append(f"Details: {details}")
        if die_results and packer != 'None':
            report.append("\nDIE Findings:")
            for detect in die_results.get('detects', []):
                if detect['type'].lower() in ['packer', 'protector', 'compiler']:
                    report.append(f"- {detect['name']} ({detect['type']})")
    
    full_report = "\n".join(report)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(full_report)
    
    return full_report

def main():
    parser = argparse.ArgumentParser(description='Malware unpacking tool with DIE integration')
    parser.add_argument('path', help='Path to directory containing malware samples')
    parser.add_argument('--die-path', default='diec', help='Path to Detect It Easy executable')
    parser.add_argument('--report', help='Path to save detailed report')
    args = parser.parse_args()
    
    # Verify path exists
    if not os.path.exists(args.path):
        print(f"Error: Path {args.path} does not exist")
        return
    
    # Initialize DIE wrapper
    die_wrapper = DieWrapper(args.die_path)
    if die_wrapper.is_available():
        print("Detect It Easy (DIE) is available - using for enhanced detection")
    else:
        print("Detect It Easy (DIE) not found - using basic detection methods")
    
    print(f"\nStarting analysis of {args.path}")
    
    results, total_files, unpacked_files = analyze_directory(args.path, die_wrapper)
    
    # Generate and display report
    report = generate_report(results, args.report)
    print("\n" + report)
    
    # Print quick summary to console
    print("\n=== Quick Summary ===")
    print(f"Total files processed: {total_files}")
    print(f"Packed files detected: {len([r for r in results if r[2] != 'None'])}")
    print(f"Successfully unpacked: {unpacked_files}")
    
    if args.report:
        print(f"\nDetailed report saved to: {args.report}")

if __name__ == "__main__":
    # Check if python-magic and pefile are available
    try:
        import pefile
        import magic
    except ImportError:
        print("Required libraries not found. Please install with:")
        print("pip install pefile python-magic")
        exit(1)
        
    main()