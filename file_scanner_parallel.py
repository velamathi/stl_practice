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
from typing import Dict, Any, List
import hashlib
import threading
import signal
from contextlib import contextmanager
import queue
import multiprocessing
from multiprocessing import Pool, Manager, Value
import psutil
import itertools
from functools import partial

# Global counter for progress tracking
file_counter = Value('i', 0)
total_size = Value('L', 0)  # 'L' for unsigned long
memory_threshold = 0.75  # Use 75% of available memory

def get_memory_usage():
    """Get current memory usage percentage"""
    process = psutil.Process(os.getpid())
    return process.memory_percent()

def process_file(args):
    """Process a single file and return its metadata"""
    file_path, root_path = args
    try:
        stats = os.stat(file_path)
        relative_path = str(Path(file_path).relative_to(root_path))
        
        # Basic file info that doesn't require additional I/O
        file_info = {
            'filename': os.path.basename(file_path),
            'path': file_path,
            'relative_path': relative_path,
            'size_bytes': stats.st_size,
            'size_human': format_size(stats.st_size),
            'created_time': datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
            'modified_time': datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'accessed_time': datetime.fromtimestamp(stats.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
            'file_extension': os.path.splitext(file_path)[1].lower(),
            'is_hidden': os.path.basename(file_path).startswith('.'),
            'is_symlink': os.path.islink(file_path),
            'parent_directory': os.path.basename(os.path.dirname(file_path)),
            'directory_depth': len(Path(relative_path).parts) - 1,
            'full_directory_path': os.path.dirname(file_path),
            'permissions': oct(stats.st_mode)[-3:],
            'owner_id': stats.st_uid,
            'group_id': stats.st_gid,
            'is_executable': bool(stats.st_mode & 0o111),
            'is_readable': os.access(file_path, os.R_OK),
            'is_writable': os.access(file_path, os.W_OK),
            'inode': stats.st_ino,
            'device_id': stats.st_dev,
            'hard_links': stats.st_nlink,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Only get MIME type and hash for readable files under size limit
        if os.access(file_path, os.R_OK) and stats.st_size < 10_000_000:
            try:
                import magic
                file_info['mime_type'] = magic.from_file(file_path, mime=True)
            except:
                file_info['mime_type'] = "unknown/unknown"
            
            try:
                hasher = hashlib.md5()
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''):
                        hasher.update(chunk)
                file_info['md5_hash'] = hasher.hexdigest()
            except:
                file_info['md5_hash'] = None
        else:
            file_info['mime_type'] = "inaccessible/unknown"
            file_info['md5_hash'] = None
        
        with file_counter.get_lock():
            file_counter.value += 1
        with total_size.get_lock():
            total_size.value += stats.st_size
            
        return file_info
    except Exception as e:
        return None

def find_files(directory_path: str, skip_hidden: bool = True):
    """Fast file finder using os.walk"""
    hidden_pattern = re.compile(r'^\.')
    skip_patterns = {
        'node_modules', '.git', '__pycache__', 
        'venv', 'env', '.venv', '.env',
        '.Trash', '$Recycle.Bin', 'System Volume Information',
        'temp', 'tmp', 'cache', '.cache',
        '.npm', '.yarn', 'dist', 'build',
        'containers/storage', 'snap'
    }
    
    def should_process_dir(dirname: str) -> bool:
        if skip_hidden and hidden_pattern.match(dirname):
            return False
        return dirname.lower() not in skip_patterns
    
    for root, dirs, files in os.walk(directory_path, followlinks=False):
        # Filter directories in-place
        dirs[:] = [d for d in dirs if should_process_dir(d)]
        
        # Yield readable files
        for name in files:
            if skip_hidden and name.startswith('.'):
                continue
            
            file_path = os.path.join(root, name)
            if os.access(file_path, os.R_OK):
                yield file_path

def save_batch(metadata: List[Dict], output_dir: Path, batch_num: int):
    """Save a batch of results to both JSON and CSV"""
    if not metadata:
        return
        
    # Save to JSON
    json_file = output_dir / f"metadata_batch_{batch_num}.json"
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(metadata, f)
    
    # Save to CSV
    csv_file = output_dir / f"metadata_batch_{batch_num}.csv"
    try:
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = set().union(*(d.keys() for d in metadata))
            writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
            writer.writeheader()
            writer.writerows(metadata)
    except Exception as e:
        logger.error(f"Error saving batch {batch_num} to CSV: {e}")

def merge_results(output_dir: Path):
    """Merge all batch files into final results"""
    all_metadata = []
    
    # Read all JSON batch files
    for batch_file in output_dir.glob("metadata_batch_*.json"):
        with open(batch_file, 'r', encoding='utf-8') as f:
            batch_data = json.load(f)
            all_metadata.extend(batch_data)
        os.remove(batch_file)  # Remove batch file after merging
    
    # Save final results
    if all_metadata:
        save_to_json(all_metadata, output_dir / "metadata.json")
        save_to_csv(all_metadata, output_dir / "metadata.csv")
    
    # Remove batch CSV files
    for batch_file in output_dir.glob("metadata_batch_*.csv"):
        os.remove(batch_file)

def main():
    parser = argparse.ArgumentParser(description='Scan directory and collect file metadata')
    parser.add_argument('--path', type=str, 
                       default=str(Path.home()),
                       help='Directory path to scan (default: home directory)')
    parser.add_argument('--skip-hidden', action='store_true',
                       help='Skip hidden files and directories')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show debug messages including permission errors')
    parser.add_argument('--max-time', type=int, default=3600,
                       help='Maximum time in seconds to run the scan (default: 1 hour)')
    parser.add_argument('--processes', type=int, 
                       default=max(1, multiprocessing.cpu_count() - 1),
                       help='Number of processes to use (default: CPU count - 1)')
    parser.add_argument('--chunk-size', type=int, default=100,
                       help='Number of files to process in each chunk (default: 100)')
    args = parser.parse_args()

    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path("file_scan_results") / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    # Setup logging
    global logger
    logger = setup_logging(output_dir)
    
    if not args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    scan_path = args.path
    logger.info(f"Starting scan of: {scan_path}")
    logger.info(f"Results will be saved to: {output_dir}")
    logger.info(f"Using {args.processes} processes")
    
    if not os.access(scan_path, os.R_OK):
        logger.error(f"No permission to read the specified directory: {scan_path}")
        return
    
    start_time = time.time()
    batch_num = 0
    results_buffer = []
    
    try:
        # Create process pool
        with Pool(processes=args.processes) as pool:
            # Find all files first
            all_files = list(find_files(scan_path, args.skip_hidden))
            total_files = len(all_files)
            logger.info(f"Found {total_files} files to process")
            
            # Process files in parallel
            process_func = partial(process_file, root_path=Path(scan_path))
            file_pairs = zip(all_files, itertools.repeat(Path(scan_path)))
            
            for result in pool.imap_unordered(process_file, file_pairs, chunksize=args.chunk_size):
                if result:
                    results_buffer.append(result)
                
                # Save batch if memory threshold is reached or buffer is large
                if (get_memory_usage() > memory_threshold or 
                    len(results_buffer) >= 10000):  # Also save if buffer is large
                    save_batch(results_buffer, output_dir, batch_num)
                    batch_num += 1
                    results_buffer = []
                
                # Log progress
                if file_counter.value % 1000 == 0:
                    current_time = time.time()
                    elapsed_time = current_time - start_time
                    speed = file_counter.value / elapsed_time if elapsed_time > 0 else 0
                    logger.info(
                        f"Processed {file_counter.value}/{total_files} files "
                        f"({(file_counter.value/total_files)*100:.1f}%). "
                        f"Total size: {format_size(total_size.value)}. "
                        f"Speed: {speed:.1f} files/second"
                    )
                
                if current_time - start_time > args.max_time:
                    logger.info("Maximum scan time reached, stopping...")
                    break
    
    except KeyboardInterrupt:
        logger.info("\nScan interrupted by user")
    finally:
        # Save any remaining results
        if results_buffer:
            save_batch(results_buffer, output_dir, batch_num)
        
        # Merge all batches into final results
        logger.info("Merging results...")
        merge_results(output_dir)
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        logger.info("\nScan Summary:")
        logger.info(f"Total files processed: {file_counter.value}")
        logger.info(f"Total size: {format_size(total_size.value)}")
        logger.info(f"Total time: {elapsed_time:.2f} seconds")
        logger.info(f"Average speed: {file_counter.value / elapsed_time:.2f} files/second")
        logger.info(f"Results saved to: {output_dir}")

if __name__ == "__main__":
    main()
