#!/usr/bin/env python3
"""
从 cve_monitor 导入 CVE 数据到分析库
======================================
整合威胁情报推送系统的漏洞数据到 CVSS 分析引擎

用法:
    python import_from_cve_monitor.py                    # 交互模式
    python import_from_cve_monitor.py --source ./external/cve_monitor/data.db  # 指定源
    python import_from_cve_monitor.py --dry-run          # 仅预览
"""

import argparse
import sqlite3
import logging
from datetime import datetime
from pathlib import Path
import re

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# 目标数据库路径
TARGET_DB = Path('~/.multi-cybersecurity/cve.db')

# 源数据库路径 (cve_monitor)
DEFAULT_SOURCE_DB = Path('./external/cve_monitor/data.db')


def parse_cve_ids(cve_ids_text: str) -> list[str]:
    """从 cve_ids 字段提取 CVE ID 列表"""
    if not cve_ids_text:
        return []

    # CVE ID 格式: CVE-YYYY-NNNNN+
    pattern = r'CVE-\d{4}-\d{4,}'
    return re.findall(pattern, cve_ids_text)


def get_source_stats(db_path: Path) -> dict:
    """获取源数据库统计"""
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
    total = cursor.fetchone()[0]

    # 按 source 统计
    cursor.execute('SELECT source, COUNT(*) FROM vulnerabilities GROUP BY source')
    by_source = dict(cursor.fetchall())

    # 提取唯一 CVE 数量
    all_cves = set()
    cursor.execute('SELECT cve_ids FROM vulnerabilities')
    for (cve_ids,) in cursor.fetchall():
        all_cves.update(parse_cve_ids(cve_ids))

    conn.close()

    return {
        'total_vulnerabilities': total,
        'unique_cves': len(all_cves),
        'by_source': by_source
    }


def get_target_stats(db_path: Path) -> dict:
    """获取目标数据库统计"""
    if not db_path.exists():
        return {'exists': False, 'total': 0, 'with_cvss': 0}

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM cve_records')
    total = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM cve_records WHERE cvss > 0')
    with_cvss = cursor.fetchone()[0]

    conn.close()

    return {'exists': True, 'total': total, 'with_cvss': with_cvss}


def import_cves(source_db: Path, target_db: Path, dry_run: bool = False) -> dict:
    """
    从 cve_monitor 导入 CVE 到分析库

    Returns:
        {'imported': N, 'skipped': M, 'errors': K}
    """
    logger.info(f'Source: {source_db}')
    logger.info(f'Target: {target_db}')

    # 确保目标目录存在
    target_db.parent.mkdir(parents=True, exist_ok=True)

    # 连接数据库
    source_conn = sqlite3.connect(str(source_db))
    target_conn = sqlite3.connect(str(target_db))

    source_cursor = source_conn.cursor()
    target_cursor = target_conn.cursor()

    # 确保目标表存在
    target_cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve_records (
            cve_id TEXT PRIMARY KEY,
            title TEXT,
            description TEXT,
            cvss REAL DEFAULT 0.0,
            cvss_vector TEXT,
            has_auth INTEGER DEFAULT 0,
            rce INTEGER DEFAULT 0,
            pre_auth INTEGER DEFAULT 1,
            source TEXT,
            detail_url TEXT,
            poc_path TEXT,
            mitre_attack_id TEXT,
            mitre_attack_name TEXT,
            affected_product TEXT,
            affected_version TEXT,
            published_date TEXT,
            modified_date TEXT,
            raw_data TEXT,
            updated_at TEXT
        )
    ''')
    target_conn.commit()

    # 获取已存在的 CVE
    target_cursor.execute('SELECT cve_id FROM cve_records')
    existing = set(row[0] for row in target_cursor.fetchall())

    # 从 source 获取所有漏洞
    source_cursor.execute('SELECT id, title, time, source, detail_url, cve_ids FROM vulnerabilities')
    source_rows = source_cursor.fetchall()

    imported = 0
    skipped = 0
    errors = 0

    for row in source_rows:
        vuln_id, title, time, source, detail_url, cve_ids = row

        # 提取 CVE ID 列表
        cve_list = parse_cve_ids(cve_ids or '')

        if not cve_list:
            # 如果没有 CVE ID，用 vuln_id 作为 fallback（通常是 CVE-YYYY-XXXXX 格式）
            if vuln_id.startswith('CVE-'):
                cve_list = [vuln_id]

        for cve_id in cve_list:
            if cve_id in existing:
                skipped += 1
                continue

            try:
                if dry_run:
                    logger.info(f'[DRY-RUN] Would import: {cve_id} - {title[:30]}...')
                else:
                    target_cursor.execute('''
                        INSERT OR IGNORE INTO cve_records (
                            cve_id, title, description, source, detail_url, published_date, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        cve_id,
                        title or '',
                        f'Source: {source}' if source else '',
                        source or '',
                        detail_url or '',
                        time or '',
                        datetime.now().isoformat()
                    ))
                imported += 1
            except Exception as e:
                logger.warning(f'Error importing {cve_id}: {e}')
                errors += 1

            existing.add(cve_id)  # 防止重复插入

    if not dry_run:
        target_conn.commit()

    source_conn.close()
    target_conn.close()

    return {
        'imported': imported,
        'skipped': skipped,
        'errors': errors,
        'total_source': len(source_rows)
    }


def main():
    parser = argparse.ArgumentParser(description='Import CVEs from cve_monitor to analysis database')
    parser.add_argument('--source', type=str, default=str(DEFAULT_SOURCE_DB),
                        help='Source cve_monitor database path')
    parser.add_argument('--target', type=str, default=str(TARGET_DB),
                        help='Target analysis database path')
    parser.add_argument('--dry-run', action='store_true',
                        help='Preview changes without importing')

    args = parser.parse_args()

    source_path = Path(args.source)
    target_path = Path(args.target).expanduser()

    print('=' * 60)
    print('CVE Monitor → Analysis Database Importer')
    print('=' * 60)

    # 统计
    print('\n[1] Source Database (cve_monitor)')
    if source_path.exists():
        stats = get_source_stats(source_path)
        print(f'    Vulnerabilities: {stats["total_vulnerabilities"]}')
        print(f'    Unique CVEs: {stats["unique_cves"]}')
        print(f'    By source:')
        for src, cnt in stats['by_source'].items():
            print(f'      - {src}: {cnt}')
    else:
        print(f'    ERROR: Source database not found: {source_path}')
        return

    print('\n[2] Target Database (analysis)')
    target_stats = get_target_stats(target_path)
    if target_stats['exists']:
        print(f'    Total CVEs: {target_stats["total"]}')
        print(f'    With CVSS: {target_stats["with_cvss"]}')
        print(f'    Missing CVSS: {target_stats["total"] - target_stats["with_cvss"]}')
    else:
        print(f'    Does not exist, will be created')

    print('\n[3] Import')
    if args.dry_run:
        print('    Mode: DRY-RUN (no changes will be made)')

    result = import_cves(source_path, target_path, dry_run=args.dry_run)

    print(f'\n    Result:')
    print(f'      Imported: {result["imported"]}')
    print(f'      Skipped (existing): {result["skipped"]}')
    print(f'      Errors: {result["errors"]}')

    if not args.dry_run:
        print('\n[4] Updated Target Stats')
        new_stats = get_target_stats(target_path)
        print(f'    Total CVEs: {new_stats["total"]}')
        print(f'    With CVSS: {new_stats["with_cvss"]}')
        print(f'    Missing CVSS: {new_stats["total"] - new_stats["with_cvss"]}')

    print('\n' + '=' * 60)
    print('Next steps:')
    print('  1. Run: python tools/sync_cve_cvss.py --mode full --limit 10000')
    print('  2. This will fetch CVSS scores from NVD API')
    print('=' * 60)


if __name__ == '__main__':
    main()
