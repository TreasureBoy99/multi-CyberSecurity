#!/usr/bin/env python3
"""
CVE CVSS 数据同步工具
=====================
从 NVD API 批量获取 CVSS 评分并更新本地数据库

用法:
    # 增量更新 (最近7天)
    python sync_cve_cvss.py --mode incremental

    # 全量补充 2020-2026 CVSS
    python sync_cve_cvss.py --mode full --limit 5000

    # 只更新特定 CVE
    python sync_cve_cvss.py --cves CVE-2021-44228 CVE-2022-22965
"""

import argparse
import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import urllib.request
import urllib.error

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# NVD API 配置
NVD_API_KEY = os.environ.get('NVD_API_KEY', '')
NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

# 速率限制 (NVD API: 有key 50/10s, 无key 5/10s)
REQUEST_INTERVAL_WITH_KEY = 0.2
REQUEST_INTERVAL_WITHOUT_KEY = 2.0
BATCH_SIZE = 100  # NVD API 2.0 单次最多100个CVE


class CVSSSyncer:
    """CVSS 数据同步器"""

    def __init__(self, db_path: str = '~/.multi-cybersecurity/cve.db'):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.api_key = NVD_API_KEY
        self.request_interval = REQUEST_INTERVAL_WITH_KEY if self.api_key else REQUEST_INTERVAL_WITHOUT_KEY

    def _get_headers(self) -> dict:
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'multi-cybersecurity-cve-sync/1.0'
        }
        if self.api_key:
            headers['apiKey'] = self.api_key
        return headers

    def _rate_limit(self):
        time.sleep(self.request_interval)

    def _ensure_db(self):
        """确保数据库存在"""
        if not self.db_path.exists():
            logger.info('Creating new CVE database...')
            conn = sqlite3.connect(str(self.db_path))
            conn.execute('''
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
            conn.commit()
            conn.close()

    def fetch_cve_batch(self, cve_ids: list[str]) -> dict:
        """批量获取 CVE 数据"""
        if not cve_ids:
            return {}

        self._rate_limit()
        cve_id_param = ','.join(cve_ids)
        url = f'{NVD_BASE_URL}?cveId={cve_id_param}'

        try:
            req = urllib.request.Request(url, headers=self._get_headers())
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode('utf-8'))

            results = {}
            for v in data.get('vulnerabilities', []):
                cve_id = v['cve']['id']
                results[cve_id] = v['cve']
            return results
        except urllib.error.HTTPError as e:
            logger.error(f'HTTP Error {e.code}: {e.reason}')
        except Exception as e:
            logger.error(f'Fetch error: {e}')
        return {}

    def extract_cvss(self, vuln: dict) -> dict:
        """从 NVD CVE 数据提取 CVSS"""
        metrics = vuln.get('metrics', {})
        for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if version in metrics and metrics[version]:
                m = metrics[version][0]
                cvss = m.get('cvssData', {})
                return {
                    'cvss': cvss.get('baseScore', 0.0),
                    'cvss_vector': cvss.get('vectorString', ''),
                    'base_severity': cvss.get('baseSeverity', '')
                }
        return {'cvss': 0.0, 'cvss_vector': '', 'base_severity': ''}

    def update_batch_cvss(self, updates: dict) -> int:
        """批量更新 CVSS 数据"""
        if not updates:
            return 0

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        now = datetime.now().isoformat()

        updated = 0
        for cve_id, cvss_data in updates.items():
            cursor.execute('''
                UPDATE cve_records
                SET cvss = ?, cvss_vector = ?, updated_at = ?
                WHERE cve_id = ?
            ''', (cvss_data['cvss'], cvss_data['cvss_vector'], now, cve_id))
            if cursor.rowcount > 0:
                updated += 1

        conn.commit()
        conn.close()
        return updated

    def get_cves_needing_cvss(self, limit: int = 5000) -> list[str]:
        """获取需要补充 CVSS 的 CVE"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute('''
            SELECT cve_id FROM cve_records
            WHERE cvss = 0 OR cvss IS NULL
            ORDER BY cve_id DESC
            LIMIT ?
        ''', (limit,))
        results = [row[0] for row in cursor.fetchall()]
        conn.close()
        return results

    def get_local_cves(self) -> set:
        """获取本地所有 CVE"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute('SELECT cve_id FROM cve_records')
        results = set(row[0] for row in cursor.fetchall())
        conn.close()
        return results

    def get_recent_modified_cves(self, days: int = 7) -> list[str]:
        """获取最近修改的 CVE"""
        self._rate_limit()
        pub_start = (datetime.now() - timedelta(days=days)).isoformat() + '+00:00'
        url = f'{NVD_BASE_URL}?pubStartDate={pub_start}&resultsPerPage=1000'

        try:
            req = urllib.request.Request(url, headers=self._get_headers())
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode('utf-8'))
            return [v['cve']['id'] for v in data.get('vulnerabilities', [])]
        except Exception as e:
            logger.error(f'Failed to get recent CVEs: {e}')
        return []

    def sync_incremental(self) -> int:
        """增量同步最近修改的 CVE"""
        logger.info('Starting incremental sync...')

        existing = self.get_local_cves()
        recent = self.get_recent_modified_cves(7)
        logger.info(f'Found {len(recent)} recently modified CVEs in NVD')

        to_fetch = [c for c in recent if c in existing]
        logger.info(f'Need to fetch {len(to_fetch)} CVEs')

        updated = 0
        for i in range(0, len(to_fetch), BATCH_SIZE):
            batch = to_fetch[i:i+BATCH_SIZE]
            cve_data = self.fetch_cve_batch(batch)

            updates = {}
            for cve_id, vuln in cve_data.items():
                cvss = self.extract_cvss(vuln)
                if cvss['cvss'] > 0:
                    updates[cve_id] = cvss

            if updates:
                updated += self.update_batch_cvss(updates)

            logger.info(f'Progress: {min(i+BATCH_SIZE, len(to_fetch))}/{len(to_fetch)} ({updated} updated)')

        logger.info(f'Incremental sync complete: {updated} CVEs updated')
        return updated

    def sync_full(self, limit: int = 10000) -> int:
        """全量同步"""
        logger.info(f'Starting full sync (limit={limit})...')

        cves = self.get_cves_needing_cvss(limit)
        logger.info(f'Found {len(cves)} CVEs needing CVSS update')

        updated = 0
        for i in range(0, len(cves), BATCH_SIZE):
            batch = cves[i:i+BATCH_SIZE]
            cve_data = self.fetch_cve_batch(batch)

            updates = {}
            for cve_id, vuln in cve_data.items():
                cvss = self.extract_cvss(vuln)
                if cvss['cvss'] > 0:
                    updates[cve_id] = cvss

            if updates:
                updated += self.update_batch_cvss(updates)

            if (i // BATCH_SIZE + 1) % 10 == 0:
                logger.info(f'Progress: {min(i+BATCH_SIZE, len(cves))}/{len(cves)} ({updated} updated)')

        logger.info(f'Full sync complete: {updated} CVEs updated')
        return updated

    def sync_specific(self, cve_ids: list[str]) -> int:
        """同步指定的 CVE"""
        logger.info(f'Syncing {len(cve_ids)} specific CVEs...')

        updated = 0
        for i in range(0, len(cve_ids), BATCH_SIZE):
            batch = cve_ids[i:i+BATCH_SIZE]
            cve_data = self.fetch_cve_batch(batch)

            updates = {}
            for cve_id, vuln in cve_data.items():
                cvss = self.extract_cvss(vuln)
                if cvss['cvss'] > 0:
                    updates[cve_id] = cvss

            if updates:
                updated += self.update_batch_cvss(updates)

            logger.info(f'Progress: {min(i+BATCH_SIZE, len(cve_ids))}/{len(cve_ids)} ({updated} updated)')

        logger.info(f'Specific sync complete: {updated} CVEs updated')
        return updated

    def stats(self):
        """显示数据库统计"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM cve_records')
        total = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM cve_records WHERE cvss > 0')
        with_cvss = cursor.fetchone()[0]

        cursor.execute('SELECT AVG(cvss) FROM cve_records WHERE cvss > 0')
        avg_cvss = cursor.fetchone()[0] or 0

        cursor.execute('SELECT COUNT(*) FROM cve_records WHERE cvss >= 9.0')
        critical = cursor.fetchone()[0]

        print(f'\n=== CVE Database Stats ===')
        print(f'Total CVEs: {total}')
        print(f'With CVSS: {with_cvss} ({with_cvss/total*100:.1f}%)')
        print(f'Missing CVSS: {total - with_cvss}')
        print(f'Average CVSS: {avg_cvss:.2f}')
        print(f'Critical (CVSS>=9.0): {critical}')
        print(f'API Key: {"Yes" if self.api_key else "No"}')

        conn.close()


def main():
    parser = argparse.ArgumentParser(description='Sync CVSS data from NVD')
    parser.add_argument('--db', default='~/.multi-cybersecurity/cve.db', help='Database path')
    parser.add_argument('--mode', choices=['incremental', 'full'], default='incremental',
                        help='Sync mode')
    parser.add_argument('--limit', type=int, default=10000, help='Max CVEs to process in full mode')
    parser.add_argument('--cves', nargs='+', help='Specific CVE IDs to sync')
    parser.add_argument('--stats', action='store_true', help='Show database statistics')

    args = parser.parse_args()

    syncer = CVSSSyncer(db_path=args.db)
    syncer._ensure_db()

    if args.stats:
        syncer.stats()
        return

    if args.cves:
        syncer.sync_specific(args.cves)
    elif args.mode == 'incremental':
        syncer.sync_incremental()
    else:
        syncer.sync_full(limit=args.limit)

    # 显示更新后的统计
    syncer.stats()


if __name__ == '__main__':
    main()
