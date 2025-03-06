#!/usr/bin/env python3

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
import hashlib
from concurrent.futures import ThreadPoolExecutor
import threading
import signal
from contextlib import contextmanager

# Global counter for progress tracking
file_counter = 0
counter_lock = threading.Lock()

class TimeoutException(Exception):
    pass

@contextmanager
def timeout(seconds):
    def timeout_handler(signum, frame):
        raise TimeoutException("Operation timed out")
    
    # Register a function to raise a TimeoutException on the signal
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    
    try:
        yield
    finally:
        # Disable the alarm
        signal.alarm(0)

def setup_logging(log_dir: Path) -> logging.Logger:
    """Configure logging to both file and console"""
    logger = logging.getLogger('file_scanner')
    logger.setLevel(logging.INFO)
    
    # Create formatters
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_formatter = logging.Formatter('%(message)s')
    
    # Create and configure file handler
    file_handler = logging.FileHandler(log_dir / 'scan.log')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(file_formatter)
    
    # Create and configure console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def format_size(size_bytes: int) -> str:
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"

def save_to_json(metadata: list[Dict[str, Any]], output_path: Path) -> None:
    """Save metadata to JSON file"""
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

def save_to_csv(metadata: list[Dict[str, Any]], output_path: Path) -> None:
    """Save metadata to CSV file"""
    if not metadata:
        return
    
    try:
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            # Get all possible keys from all dictionaries
            fieldnames = set()
            for entry in metadata:
                fieldnames.update(entry.keys())
            
            writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
            writer.writeheader()
            
            # Write each row, ensuring missing fields are handled
            for entry in metadata:
                # Ensure all fields exist in each row
                row = {field: entry.get(field, '') for field in fieldnames}
                writer.writerow(row)
    except Exception as e:
        logger.error(f"Error saving to CSV {output_path}: {e}")

def get_mime_type(file_path: str) -> str:
    """Safely get MIME type of file with timeout"""
    try:
        with timeout(2):  # 2 second timeout for mime type detection
            import magic
            return magic.from_file(file_path, mime=True)
    except (ImportError, TimeoutException, Exception) as e:
        logger.debug(f"MIME type detection failed for {file_path}: {str(e)}")
        return "unknown/unknown"

def get_hash(file_path: str, block_size: int = 65536) -> str:
    """Calculate MD5 hash for small files with timeout"""
    try:
        if os.path.getsize(file_path) > 10_000_000:  # Skip files larger than 10MB
            return None
        
        with timeout(5):  # 5 second timeout for hash calculation
            hasher = hashlib.md5()
            with open(file_path, 'rb') as f:
                buf = f.read(block_size)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = f.read(block_size)
            return hasher.hexdigest()
    except (TimeoutException, Exception) as e:
        logger.debug(f"Hash calculation failed for {file_path}: {str(e)}")
        return None

def walk_files_lazy(directory_path: str, skip_hidden: bool = True, batch_size: int = 1000):
    """
    Generator function to walk directory tree and yield file metadata in batches.
    """
    global file_counter
    last_progress_time = time.time()
    
    # Pre-compile patterns for better performance
    hidden_pattern = re.compile(r'^\.')
    
    # Common directories to skip
    skip_patterns = {
        'node_modules', '.git', '__pycache__', 
        'venv', 'env', '.venv', '.env',
        '.Trash', '$Recycle.Bin', 'System Volume Information',
        'temp', 'tmp', 'cache', '.cache',
        '.npm', '.yarn', 'dist', 'build',
        'containers/storage', 'snap'  # Skip container and snap directories
    }
    
    def should_process_dir(dirname: str, full_path: str) -> bool:
        """Check if directory should be processed"""
        try:
            if skip_hidden and hidden_pattern.match(dirname):
                return False
            if dirname.lower() in skip_patterns:
                return False
            # Skip if we don't have read permission
            if not os.access(full_path, os.R_OK):
                return False
            return True
        except Exception as e:
            logger.debug(f"Error checking directory {full_path}: {e}")
            return False
    
    def fast_walk(top: str):
        """Efficient directory walker using scandir"""
        nonlocal last_progress_time
        current_time = time.time()
        
        # Print progress every 5 seconds
        if current_time - last_progress_time >= 5:
            logger.debug(f"Currently scanning: {top}")
            last_progress_time = current_time
        
        dirs = []
        files = []
        
        try:
            # First check if we have permission to read this directory
            if not os.access(top, os.R_OK):
                logger.debug(f"Skipping directory due to permissions: {top}")
                return
            
            with timeout(10):  # 10 second timeout for directory scanning
                for entry in os.scandir(top):
                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                        if is_dir:
                            if should_process_dir(entry.name, entry.path):
                                dirs.append(entry)
                        else:
                            if os.access(entry.path, os.R_OK):  # Only add files we can read
                                files.append(entry)
                    except OSError as e:
                        logger.debug(f"Skipping {entry.path}: {e}")
                        continue
                    except Exception as e:
                        logger.debug(f"Unexpected error for {entry.path}: {e}")
                        continue
        except TimeoutException:
            logger.debug(f"Directory scan timed out for: {top}")
            return
        except OSError as e:
            logger.debug(f"Skipping directory {top}: {e}")
            return
        except Exception as e:
            logger.debug(f"Unexpected error scanning {top}: {e}")
            return

        yield top, dirs, files
        
        for dir_entry in dirs:
            try:
                yield from fast_walk(dir_entry.path)
            except Exception as e:
                logger.debug(f"Error walking {dir_entry.path}: {e}")
                continue

    # Create a buffer for batch processing
    buffer = []
    root_path = Path(directory_path)
    
    for root, dirs, files in fast_walk(directory_path):
        if not root or not files:  # Skip if no files or invalid root
            continue
            
        for file_entry in files:
            try:
                with counter_lock:
                    file_counter += 1
                
                with timeout(3):  # 3 second timeout for file stat operations
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
                    'mime_type': get_mime_type(file_path) if os.access(file_path, os.R_OK) else "inaccessible/unknown",
                    
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
                    'md5_hash': get_hash(file_path) if os.access(file_path, os.R_OK) else None,
                    
                    # Scan metadata
                    'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                buffer.append(file_info)
                
                if len(buffer) >= batch_size:
                    yield buffer
                    buffer = []
                
            except TimeoutException:
                logger.debug(f"Operation timed out for file: {file_entry.path}")
                continue
            except OSError as e:
                logger.debug(f"Error processing file {file_entry.path}: {e}")
                continue
            except Exception as e:
                logger.debug(f"Unexpected error processing {file_entry.path}: {e}")
                continue
    
    if buffer:
        yield buffer

def main():
    parser = argparse.ArgumentParser(description='Scan directory and collect file metadata')
    parser.add_argument('--path', type=str, 
                       default=str(Path.home()),
                       help='Directory path to scan (default: home directory)')
    parser.add_argument('--batch-size', type=int, 
                       default=1000,
                       help='Number of files to process in each batch (default: 1000)')
    parser.add_argument('--skip-hidden', action='store_true',
                       help='Skip hidden files and directories')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show debug messages including permission errors')
    parser.add_argument('--max-time', type=int, default=3600,
                       help='Maximum time in seconds to run the scan (default: 1 hour)')
    args = parser.parse_args()

    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path("file_scan_results") / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    # Setup logging
    global logger
    logger = setup_logging(output_dir)
    
    # Set logging level based on verbosity
    if not args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    scan_path = args.path
    logger.info(f"Starting scan of: {scan_path}")
    logger.info(f"Results will be saved to: {output_dir}")
    
    if not os.access(scan_path, os.R_OK):
        logger.error(f"No permission to read the specified directory: {scan_path}")
        return
    
    # Setup output files
    json_file = output_dir / "metadata.json"
    csv_file = output_dir / "metadata.csv"
    
    start_time = time.time()
    total_size = 0
    all_metadata = []
    last_save_time = start_time
    
    try:
        for batch in walk_files_lazy(scan_path, 
                                   skip_hidden=args.skip_hidden,
                                   batch_size=args.batch_size):
            if not batch:  # Skip empty batches
                continue
            
            current_time = time.time()
            if current_time - start_time > args.max_time:
                logger.info("Maximum scan time reached, stopping scan...")
                break
                
            total_size += sum(file_info['size_bytes'] for file_info in batch)
            all_metadata.extend(batch)
            
            # Log progress
            elapsed_time = current_time - start_time
            files_per_second = file_counter / elapsed_time if elapsed_time > 0 else 0
            logger.info(
                f"Processed {file_counter} files. "
                f"Total size: {format_size(total_size)}. "
                f"Speed: {files_per_second:.2f} files/second"
            )
            
            # Save intermediate results every 5 minutes
            if current_time - last_save_time >= 300:
                logger.info(f"Saving intermediate results ({len(all_metadata)} files processed so far)...")
                save_to_json(all_metadata, json_file)
                save_to_csv(all_metadata, csv_file)
                last_save_time = current_time
                
    except KeyboardInterrupt:
        logger.info("\nScan interrupted by user")
    finally:
        # Save final results
        if all_metadata:  # Only save if we have data
            logger.info(f"Saving final results ({len(all_metadata)} files total)...")
            save_to_json(all_metadata, json_file)
            save_to_csv(all_metadata, csv_file)
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        logger.info("\nScan Summary:")
        logger.info(f"Total files processed: {file_counter}")
        logger.info(f"Total size: {format_size(total_size)}")
        logger.info(f"Total time: {elapsed_time:.2f} seconds")
        logger.info(f"Average speed: {file_counter / elapsed_time:.2f} files/second")
        logger.info(f"Results saved to: {output_dir}")

if __name__ == "__main__":
    main()
