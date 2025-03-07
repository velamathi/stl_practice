#!/usr/bin/env python3

import os
import re
from datetime import datetime
import time
from pathlib import Path
import csv
import logging
import argparse
from typing import Dict, Any, List, Set, Generator, Tuple, Optional
import hashlib
import multiprocessing
from multiprocessing import Pool, Value, Process, Manager, Queue
import queue
import psutil
import numpy as np
from collections import deque
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import threading
import signal
from contextlib import contextmanager
import sqlite3
import mmap
from functools import partial
from tqdm import tqdm
import sys
import shutil

# Global counters for progress tracking
file_counter = Value('i', 0)
total_size = Value('L', 0)  # unsigned long for file sizes
memory_threshold = 0.75  # 75% memory usage threshold

class DatabaseManager:
    """Manages database connections and operations"""
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = None
        self.setup_database()
    
    def setup_database(self):
        """Initialize database and create tables"""
        self.conn = sqlite3.connect(str(self.db_path))
        with self.conn:
            # Create tables with optimized indexes
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT UNIQUE,
                    size_bytes INTEGER,
                    modified_time TEXT,
                    file_type TEXT,
                    is_symlink INTEGER,
                    is_broken_link INTEGER,
                    batch_id INTEGER,
                    processed_time TEXT
                )
            """)
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_path ON files(path)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_batch ON files(batch_id)")
    
    def add_file(self, file_info: Dict[str, Any], batch_id: int):
        """Add file to database"""
        with self.conn:
            self.conn.execute("""
                INSERT OR REPLACE INTO files (
                    path, size_bytes, modified_time, file_type, 
                    is_symlink, is_broken_link, batch_id, processed_time
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                file_info['path'],
                file_info['size_bytes'],
                file_info['modified_time'],
                file_info['file_extension'],
                file_info.get('is_symlink', 0),
                file_info.get('is_broken_link', 0),
                batch_id,
                datetime.now().isoformat()
            ))
    
    def get_progress(self) -> Tuple[int, int]:
        """Get progress statistics"""
        cursor = self.conn.execute("""
            SELECT COUNT(*), SUM(size_bytes)
            FROM files
        """)
        count, total_size = cursor.fetchone()
        return count or 0, total_size or 0
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

class ChunkedWriter:
    """Efficient chunked file writing"""
    def __init__(self, output_dir: Path, chunk_size: int = 1_000_000):
        self.output_dir = output_dir
        self.chunk_size = chunk_size
        self.current_chunk = 0
        self.buffer: List[Dict] = []
        self.lock = threading.Lock()
        self.fieldnames: Set[str] = set()
        self.final_csv = output_dir / "metadata.csv"
        self.chunks_dir = output_dir / "chunks"
        self.chunks_dir.mkdir(exist_ok=True)
        
    def write_chunk(self, chunk: List[Dict], chunk_num: int):
        """Write a chunk of data to CSV"""
        if not chunk:
            return
            
        chunk_file = self.chunks_dir / f"chunk_{chunk_num}.csv"
        # Update fieldnames with new fields from current chunk
        self.fieldnames.update(*(d.keys() for d in chunk))
        
        with open(chunk_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=sorted(self.fieldnames))
            writer.writeheader()
            writer.writerows(chunk)
    
    def add_result(self, result: Dict):
        """Add a result to the current chunk"""
        with self.lock:
            self.buffer.append(result)
            if len(self.buffer) >= self.chunk_size:
                self.flush()
    
    def flush(self):
        """Flush current buffer to disk"""
        if not self.buffer:
            return
            
        with self.lock:
            self.write_chunk(self.buffer, self.current_chunk)
            self.current_chunk += 1
            self.buffer = []
    
    def merge_chunks(self):
        """Merge all chunks into final CSV file"""
        if not self.fieldnames:
            return
            
        # Write the final CSV file with all fields
        with open(self.final_csv, 'w', newline='', encoding='utf-8') as final_file:
            writer = csv.DictWriter(final_file, fieldnames=sorted(self.fieldnames))
            writer.writeheader()
            
            # Process each chunk
            chunk_files = sorted(self.chunks_dir.glob("chunk_*.csv"))
            for chunk_file in chunk_files:
                with open(chunk_file, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        writer.writerow(row)
                
                # Remove processed chunk
                chunk_file.unlink()
            
        # Remove chunks directory if empty
        if self.chunks_dir.exists():
            self.chunks_dir.rmdir()

class MassiveTreeWalker:
    """Memory-efficient massive tree traversal"""
    def __init__(self, root: str, batch_size: int = 10000):
        self.root = root
        self.batch_size = batch_size
        self.skip_patterns = {
            # Standard skip patterns
            'node_modules', '.git', '__pycache__', 
            'venv', 'env', '.venv', '.env',
            '.Trash', '$Recycle.Bin', 'System Volume Information',
            'temp', 'tmp', 'cache', '.cache',
            '.npm', '.yarn', 'dist', 'build',
            
            # Fedora and system-specific paths
            'containers/storage',  # Container storage
            'containers/overlay',  # Container overlays
            'containers/cache',    # Container cache
            'var/lib/containers', # Container data
            'var/cache',         # System cache
            'var/tmp',           # System temp
            'proc',             # Process information
            'sys',              # System files
            'run',              # Runtime files
            'boot',            # Boot files
            'snap',            # Snap packages
            'selinux',         # SELinux
            'lost+found',      # File system recovery
            '.local/share/containers',  # User container storage
            'ostree',          # OSTree storage
            'flatpak',         # Flatpak packages
        }
        
        # Additional system paths to skip
        self.skip_prefixes = {
            '/var/lib/docker',
            '/var/lib/containers',
            '/var/lib/kubelet',
            '/var/lib/crio',
            '/proc',
            '/sys',
            '/run',
            '/boot',
            '/.snapshots',
        }
        self.hidden_pattern = re.compile(r'^\.')
    
    def should_process(self, path: str) -> bool:
        """Check if path should be processed"""
        name = os.path.basename(path)
        full_path = os.path.abspath(path)
        
        # Skip based on name
        if (name.lower() in self.skip_patterns or 
            name.startswith('.')):
            return False
            
        # Skip based on full path prefixes
        if any(full_path.startswith(prefix) for prefix in self.skip_prefixes):
            return False
            
        # Skip common system paths
        if any(part in self.skip_patterns for part in full_path.split(os.sep)):
            return False
            
        return True
    
    def walk_batch(self) -> Generator[List[str], None, None]:
        """Walk directory tree in batches"""
        batch: List[str] = []
        
        for root, dirs, files in os.walk(self.root):
            # Filter directories in-place
            dirs[:] = [d for d in dirs if self.should_process(os.path.join(root, d))]
            
            # Process files
            for name in files:
                path = os.path.join(root, name)
                if self.should_process(path):
                    batch.append(path)
                    
                    if len(batch) >= self.batch_size:
                        yield batch
                        batch = []
        
        if batch:
            yield batch

class ProgressStats:
    """Track detailed processing statistics"""
    def __init__(self):
        self.start_time = time.time()
        self.total_files = Value('i', 0)
        self.total_size = Value('L', 0)
        self.processed_files = Value('i', 0)
        self.broken_links = Value('i', 0)
        self.symlinks = Value('i', 0)
        self.errors = Value('i', 0)
        self.current_speed = Value('d', 0.0)
        self.peak_memory = Value('d', 0.0)
        
    def update(self):
        """Update statistics"""
        current_memory = psutil.Process().memory_percent()
        with self.peak_memory.get_lock():
            if current_memory > self.peak_memory.value:
                self.peak_memory.value = current_memory
        
        elapsed = time.time() - self.start_time
        if elapsed > 0:
            with self.current_speed.get_lock():
                self.current_speed.value = self.processed_files.value / elapsed

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        return {
            'total_files': self.total_files.value,
            'processed_files': self.processed_files.value,
            'total_size': format_size(self.total_size.value),
            'broken_links': self.broken_links.value,
            'symlinks': self.symlinks.value,
            'errors': self.errors.value,
            'speed': self.current_speed.value,
            'peak_memory': self.peak_memory.value
        }

class ProgressDisplay:
    """Handle progress display and updates"""
    def __init__(self, total_files: int = 0):
        self.terminal_width = shutil.get_terminal_size().columns
        self.pbar = tqdm(
            total=total_files,
            unit='files',
            unit_scale=True,
            ncols=self.terminal_width,
            bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]'
        )
        self.stats = ProgressStats()
        self.last_update = time.time()
        self.update_interval = 0.5  # Update every 0.5 seconds
        
    def update(self, n: int = 1, **kwargs):
        """Update progress bar and statistics"""
        current_time = time.time()
        if current_time - self.last_update >= self.update_interval:
            self.stats.update()
            stats = self.stats.get_stats()
            
            # Update progress bar
            self.pbar.set_postfix({
                'Speed': f"{stats['speed']:.1f} files/s",
                'Memory': f"{stats['peak_memory']:.1f}%",
                'Size': stats['total_size'],
                'Links': stats['symlinks'],
                'Broken': stats['broken_links'],
                'Errors': stats['errors']
            })
            self.last_update = current_time
        
        self.pbar.update(n)
    
    def close(self):
        """Close progress bar and display final statistics"""
        self.pbar.close()
        stats = self.stats.get_stats()
        
        # Print final statistics in a formatted box
        width = self.terminal_width - 4
        print("\n" + "=" * width)
        print("Scan Summary".center(width))
        print("-" * width)
        print(f"Total Files Processed: {stats['processed_files']:,}")
        print(f"Total Data Processed: {stats['total_size']}")
        print(f"Symbolic Links Found: {stats['symlinks']:,}")
        print(f"Broken Links Found: {stats['broken_links']:,}")
        print(f"Errors Encountered: {stats['errors']:,}")
        print(f"Peak Memory Usage: {stats['peak_memory']:.1f}%")
        print(f"Average Speed: {stats['speed']:.1f} files/second")
        print("=" * width + "\n")

def process_file(path: str, root_path: str, progress: ProgressDisplay) -> Optional[Dict[str, Any]]:
    """Process a single file with progress tracking"""
    try:
        is_symlink = os.path.islink(path)
        is_broken_link = False
        link_target = None
        
        if is_symlink:
            with progress.stats.symlinks.get_lock():
                progress.stats.symlinks.value += 1
            try:
                link_target = os.readlink(path)
                target_path = os.path.join(os.path.dirname(path), link_target)
                is_broken_link = not os.path.exists(target_path)
                if is_broken_link:
                    with progress.stats.broken_links.get_lock():
                        progress.stats.broken_links.value += 1
            except (OSError, PermissionError):
                is_broken_link = True
                with progress.stats.broken_links.get_lock():
                    progress.stats.broken_links.value += 1
        
        stats = os.lstat(path)
        relative_path = str(Path(path).relative_to(root_path))
        
        file_info = {
            'filename': os.path.basename(path),
            'path': path,
            'relative_path': relative_path,
            'size_bytes': stats.st_size,
            'size_human': format_size(stats.st_size),
            'modified_time': datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'file_extension': os.path.splitext(path)[1].lower(),
            'directory_depth': relative_path.count(os.sep),
            'full_directory_path': os.path.dirname(path),
            'permissions': oct(stats.st_mode)[-3:],
            'is_readable': os.access(path, os.R_OK),
            'is_symlink': is_symlink,
            'is_broken_link': is_broken_link,
            'link_target': link_target if is_symlink else None
        }
        
        # Update size statistics
        with progress.stats.total_size.get_lock():
            progress.stats.total_size.value += stats.st_size
        
        return file_info
    except Exception as e:
        with progress.stats.errors.get_lock():
            progress.stats.errors.value += 1
        return None

def process_batch(batch: List[str], root_path: str, num_threads: int, progress: ProgressDisplay) -> List[Dict]:
    """Process a batch of files using thread pool with progress tracking"""
    results = []
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(process_file, path, root_path, progress)
            for path in batch
        ]
        for future in futures:
            try:
                result = future.result()
                if result:
                    results.append(result)
                    progress.update(1)
            except Exception:
                with progress.stats.errors.get_lock():
                    progress.stats.errors.value += 1
                continue
    return results

def format_size(size_bytes: int) -> str:
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"

def main():
    parser = argparse.ArgumentParser(description='Massive file system scanner')
    parser.add_argument('--path', type=str, 
                       default=str(Path.home()),
                       help='Directory path to scan')
    parser.add_argument('--processes', type=int, 
                       default=max(1, multiprocessing.cpu_count() - 1),
                       help='Number of processes')
    parser.add_argument('--batch-size', type=int, 
                       default=10000,
                       help='Batch size for processing')
    parser.add_argument('--chunk-size', type=int,
                       default=1_000_000,
                       help='Number of files per chunk')
    parser.add_argument('--max-time', type=int,
                       default=86400,  # 24 hours
                       help='Maximum runtime in seconds')
    args = parser.parse_args()

    # Setup output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(f"scan_results_{timestamp}")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Initialize components
    db = DatabaseManager(output_dir / "progress.db")
    writer = ChunkedWriter(output_dir, args.chunk_size)
    walker = MassiveTreeWalker(args.path, args.batch_size)
    
    # Count total files for progress bar (quick estimation)
    print("Estimating total files...")
    total_files = sum(1 for _ in walker.walk_batch())
    progress = ProgressDisplay(total_files * args.batch_size)
    
    try:
        with Pool(processes=args.processes) as pool:
            # Process directory tree in batches
            for batch in walker.walk_batch():
                current_time = time.time()
                if current_time - progress.stats.start_time > args.max_time:
                    print("\nMaximum time reached, stopping...")
                    break
                
                # Process batch with progress tracking
                results = process_batch(batch, args.path, args.processes, progress)
                
                # Save results
                for result in results:
                    writer.add_result(result)
                    db.add_file(result, progress.stats.processed_files.value)
                
                # Check memory usage
                if psutil.Process().memory_percent() > memory_threshold:
                    writer.flush()
                    
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    finally:
        # Cleanup and display final statistics
        writer.flush()  # Flush any remaining buffer
        writer.merge_chunks()  # Merge all chunks into final CSV
        db.close()
        progress.close()
        print(f"\nResults saved to: {output_dir}/metadata.csv")

if __name__ == "__main__":
    main()
