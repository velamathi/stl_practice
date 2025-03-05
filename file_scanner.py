import os
import re
from datetime import datetime
import time
from pathlib import Path
import json
import csv
import logging
import argparse
from typing import Dict, Any

def setup_logging():
    """Configure logging to both file and console"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('file_scanner.log')
        ]
    )
    return logging.getLogger(__name__)

def save_to_json(metadata: list[Dict[str, Any]], output_path: str):
    """Save metadata to JSON file"""
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

def save_to_csv(metadata: list[Dict[str, Any]], output_path: str):
    """Save metadata to CSV file"""
    if not metadata:
        return
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=metadata[0].keys())
        writer.writeheader()
        writer.writerows(metadata)

def should_skip_directory(dirname: str, skip_patterns: set) -> bool:
    """Check if directory should be skipped based on patterns"""
    return any(pattern in dirname for pattern in skip_patterns)

def walk_files_lazy(directory_path, skip_hidden=True, batch_size=1000):
    """
    Generator function to walk directory tree and yield file metadata in batches.
    
    Args:
        directory_path (str): Root directory to start scanning
        skip_hidden (bool): Whether to skip hidden files and directories
        batch_size (int): Number of files to process before yielding results
    
    Yields:
        list[dict]: Batches of file metadata dictionaries
    """
    # Pre-compile patterns for better performance
    hidden_pattern = re.compile(r'^\.')
    
    # Common directories to skip
    skip_patterns = {
        'node_modules', '.git', '__pycache__', 
        'venv', 'env', '.venv', '.env',
        '.Trash', '$Recycle.Bin', 'System Volume Information',
        'temp', 'tmp', 'cache', '.cache',
        '.npm', '.yarn', 'dist', 'build'
    }
    
    def should_process_dir(dirname):
        """Check if directory should be processed"""
        if skip_hidden and hidden_pattern.match(dirname):
            return False
        if dirname.lower() in skip_patterns:
            return False
        return True
    
    def get_mime_type(file_path):
        """Safely get MIME type of file"""
        try:
            import magic
            return magic.from_file(file_path, mime=True)
        except (ImportError, Exception) as e:
            logger.debug(f"Could not get MIME type for {file_path}: {e}")
            return None
    
    def get_hash(file_path, block_size=65536):
        """Calculate file hash (for small files only)"""
        try:
            if os.path.getsize(file_path) > 10_000_000:  # Skip files larger than 10MB
                return None
            
            import hashlib
            hasher = hashlib.md5()
            with open(file_path, 'rb') as f:
                buf = f.read(block_size)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = f.read(block_size)
            return hasher.hexdigest()
        except Exception as e:
            logger.debug(f"Could not calculate hash for {file_path}: {e}")
            return None
    
    def fast_walk(top):
        """Efficient directory walker using scandir"""
        dirs = []
        files = []
        
        try:
            # scandir is much faster than listdir
            for entry in os.scandir(top):
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                    if is_dir:
                        if should_process_dir(entry.name):
                            dirs.append(entry)
                    else:
                        files.append(entry)
                except OSError as e:
                    logger.error(f"Error accessing {entry.path}: {e}")
                    continue
        except OSError as e:
            logger.error(f"Error scanning directory {top}: {e}")
            return

        yield top, dirs, files
        
        for dir_entry in dirs:
            try:
                yield from fast_walk(dir_entry.path)
            except OSError as e:
                logger.error(f"Error walking directory {dir_entry.path}: {e}")
                continue

    # Create a buffer for batch processing
    buffer = []
    root_path = Path(directory_path)
    
    for root, dirs, files in fast_walk(directory_path):
        for file_entry in files:
            try:
                stats = file_entry.stat(follow_symlinks=False)
                file_path = file_entry.path
                relative_path = str(Path(file_path).relative_to(root_path))
                
                file_info = {
                    # Basic information
                    'filename': file_entry.name,
                    'path': file_path,
                    'relative_path': relative_path,
                    
                    # Size information
                    'size_bytes': stats.st_size,
                    'size_human': format_size(stats.st_size),
                    
                    # Time information
                    'created_time': datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                    'modified_time': datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    'accessed_time': datetime.fromtimestamp(stats.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
                    
                    # File type information
                    'file_extension': os.path.splitext(file_entry.name)[1].lower(),
                    'is_hidden': file_entry.name.startswith('.'),
                    'is_symlink': file_entry.is_symlink(),
                    'mime_type': get_mime_type(file_path),
                    
                    # Directory information
                    'parent_directory': os.path.basename(root),
                    'directory_depth': len(Path(relative_path).parts) - 1,
                    'full_directory_path': root,
                    
                    # Permission information
                    'permissions': oct(stats.st_mode)[-3:],
                    'owner_id': stats.st_uid,
                    'group_id': stats.st_gid,
                    
                    # Additional file properties
                    'is_executable': bool(stats.st_mode & 0o111),
                    'is_readable': os.access(file_path, os.R_OK),
                    'is_writable': os.access(file_path, os.W_OK),
                    
                    # File identification
                    'inode': stats.st_ino,
                    'device_id': stats.st_dev,
                    'hard_links': stats.st_nlink,
                    
                    # Optional hash (for small files)
                    'md5_hash': get_hash(file_path) if stats.st_size <= 10_000_000 else None,
                    
                    # Scan metadata
                    'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                buffer.append(file_info)
                
                # When buffer reaches batch_size, yield the batch
                if len(buffer) >= batch_size:
                    yield buffer
                    buffer = []
                
            except OSError as e:
                logger.error(f"Error processing file {file_entry.path}: {e}")
                continue
            except Exception as e:
                logger.error(f"Unexpected error processing {file_entry.path}: {e}")
                continue
    
    # Yield any remaining items in buffer
    if buffer:
        yield buffer
        
def format_size(size_bytes):
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scan directory and collect file metadata')
    parser.add_argument('--path', type=str, 
                       default=str(Path.home()),
                       help='Directory path to scan (default: home directory)')
    parser.add_argument('--batch-size', type=int, 
                       default=1000,
                       help='Number of files to process in each batch (default: 1000)')
    args = parser.parse_args()

    logger = setup_logging()
    
    scan_path = args.path
    logger.info(f"Starting scan of: {scan_path}")
    
    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path("file_scan_results") / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Setup output files
    json_file = output_dir / "metadata.json"
    csv_file = output_dir / "metadata.csv"
    
    logger.info(f"Results will be saved to: {output_dir}")
    
    start_time = time.time()
    total_files = 0
    total_size = 0
    all_metadata = []
    
    try:
        # Process files in batches
        for batch in walk_files_lazy(scan_path, batch_size=args.batch_size):
            total_files += len(batch)
            total_size += sum(file_info['size_bytes'] for file_info in batch)
            all_metadata.extend(batch)
            
            # Log progress
            elapsed_time = time.time() - start_time
            files_per_second = total_files / elapsed_time
            logger.info(
                f"Processed {total_files} files. "
                f"Total size: {format_size(total_size)}. "
                f"Speed: {files_per_second:.2f} files/second"
            )
            
            # Periodically save to files
            if total_files % 10000 == 0:
                save_to_json(all_metadata, json_file)
                save_to_csv(all_metadata, csv_file)
                
    except KeyboardInterrupt:
        logger.info("\nScan interrupted by user")
    finally:
        # Save final results
        logger.info("Saving final results...")
        save_to_json(all_metadata, json_file)
        save_to_csv(all_metadata, csv_file)
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        logger.info("\nScan Summary:")
        logger.info(f"Total files processed: {total_files}")
        logger.info(f"Total size: {format_size(total_size)}")
        logger.info(f"Total time: {elapsed_time:.2f} seconds")
        logger.info(f"Average speed: {total_files / elapsed_time:.2f} files/second")
        logger.info(f"Results saved to: {output_dir}")
