import os
import subprocess
import pefile
import magic
import argparse
from pathlib import Path

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
    # Add more unpackers here
}

def is_packed(file_path):
    """Check if a file is packed using various heuristics"""
    try:
        # Check PE sections for common packer signatures
        pe = pefile.PE(file_path)
        
        # Check for few sections with unusual characteristics
        if len(pe.sections) < 3:
            return True
            
        # Check section names for packer indicators
        packed_section_names = ['UPX', 'FSG', '.packed', '.aspack', 'y0da']
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            if any(packed_name.lower() in section_name.lower() for packed_name in packed_section_names):
                return True
                
        # Check for common packer signatures in the binary
        with open(file_path, 'rb') as f:
            content = f.read()
            for packer, data in UNPACKERS.items():
                for signature in data.get('detection', []):
                    if signature in content:
                        return packer
                        
        # Check entry point characteristics
        if pe.OPTIONAL_HEADER.AddressOfEntryPoint < pe.OPTIONAL_HEADER.BaseOfCode:
            return True
            
    except Exception as e:
        # If PE parsing fails, it might be packed or not a PE file
        print(f"Error analyzing {file_path}: {str(e)}")
        return "Unknown (PE parsing failed)"
        
    return False

def attempt_unpack(file_path, packer):
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

def analyze_directory(directory_path):
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
            file_type = magic.from_file(file_path)
            
            # Check if packed
            packed_status = is_packed(file_path)
            
            if packed_status:
                print(f"Packed file detected: {packed_status}")
                
                if isinstance(packed_status, str) and packed_status in UNPACKERS:
                    # Attempt to unpack
                    success, message = attempt_unpack(file_path, packed_status)
                    if success:
                        print(f"Successfully unpacked to {message}")
                        unpacked_files += 1
                        results.append((file_path, packed_status, "Unpacked", message))
                    else:
                        print(f"Failed to unpack: {message}")
                        results.append((file_path, packed_status, "Failed", message))
                else:
                    print("Packed but no suitable unpacker configured")
                    results.append((file_path, packed_status, "No unpacker", ""))
            else:
                print("Not packed")
                results.append((file_path, "None", "Not packed", ""))
    
    return results, total_files, unpacked_files

def main():
    parser = argparse.ArgumentParser(description='Malware unpacking tool')
    parser.add_argument('path', help='Path to directory containing malware samples')
    args = parser.parse_args()
    
    # Verify path exists
    if not os.path.exists(args.path):
        print(f"Error: Path {args.path} does not exist")
        return
        
    print(f"\nStarting analysis of {args.path}")
    
    results, total_files, unpacked_files = analyze_directory(args.path)
    
    # Print summary
    print("\n=== Analysis Summary ===")
    print(f"Total files processed: {total_files}")
    print(f"Packed files detected: {len([r for r in results if r[1] != 'None'])}")
    print(f"Successfully unpacked: {unpacked_files}")
    
    # Print detailed results
    print("\n=== Detailed Results ===")
    for file_path, packer, status, details in results:
        print(f"\nFile: {file_path}")
        print(f"Packer: {packer}")
        print(f"Status: {status}")
        if details:
            print(f"Details: {details}")

if __name__ == "__main__":
    main()
