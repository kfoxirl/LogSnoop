"""
EMV Credit Card Transaction Log Parser Plugin

This plugin parses EMV (Europay, Mastercard, Visa) transaction logs containing:
- CIF (Customer Information File) identifiers
- Masked PANs (Primary Account Numbers)
- Tag 55 data containing EMV transaction details in TLV (Tag-Length-Value) format

Key EMV Tags parsed:
- 9F36: Application Transaction Counter (ATC)
- 9A: Transaction Date
- 9F02: Amount, Authorized
- 82: Application Interchange Profile (AIP) - indicates Magstripe vs Chip
- 95: Terminal Verification Results (TVR)
- 9F1A: Terminal Country Code (ISO 3166-1 numeric)
- 9C: Transaction Type
"""

import re
import sqlite3
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
from .base import BaseLogPlugin


class EMVPlugin(BaseLogPlugin):
    """Plugin for parsing and analyzing EMV credit card transaction logs"""
    
    # ISO 3166-1 numeric country codes
    COUNTRY_CODES = {
        '0124': 'Canada',
        '0840': 'United States',
        '0156': 'China',
        '0276': 'Germany',
        '0250': 'France',
        '0826': 'United Kingdom',
        '0392': 'Japan',
        '0036': 'Australia',
        '0484': 'Mexico',
        '0076': 'Brazil',
        '0356': 'India',
        '0380': 'Italy',
        '0724': 'Spain',
        '0528': 'Netherlands',
        '0752': 'Sweden',
        '0756': 'Switzerland',
        '0792': 'Turkey',
        '0643': 'Russia',
        '0410': 'South Korea',
        '0702': 'Singapore',
        '0158': 'Taiwan',
        '0344': 'Hong Kong',
        '0554': 'New Zealand',
        '0710': 'South Africa',
        '0218': 'Ecuador',
    }
    
    def __init__(self):
        self.transactions = []
        self.pan_fragments = {}  # CIF -> list of PAN fragments
        self.complete_pans = {}  # CIF -> complete PAN with check digit
        
    def parse(self, file_path: str) -> List[Dict]:
        """Parse EMV log file"""
        self.transactions = []
        self.pan_fragments = {}
        
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Parse CIF and PAN_MASKED line
            if line.startswith('CIF:'):
                match = re.match(r'CIF:(CIF\d+)\s+PAN_MASKED:(\d+XXX)', line)
                if match:
                    cif = match.group(1)
                    pan_masked = match.group(2)
                    
                    # Store PAN fragment
                    if cif not in self.pan_fragments:
                        self.pan_fragments[cif] = set()
                    self.pan_fragments[cif].add(pan_masked)
                    
                    # Check for tag 55 data on next line
                    if i + 1 < len(lines):
                        next_line = lines[i + 1].strip()
                        if next_line.startswith('55:'):
                            tag_data = next_line[4:].strip()
                            transaction = self._parse_tag55(tag_data, cif, pan_masked)
                            if transaction:
                                self.transactions.append(transaction)
                            i += 2
                            continue
            
            i += 1
        
        # Reconstruct complete PANs
        self._reconstruct_pans()
        
        return self.transactions
    
    def _parse_tag55(self, tag_data: str, cif: str, pan_masked: str) -> Optional[Dict]:
        """Parse EMV Tag 55 data (TLV format)"""
        try:
            tags = self._parse_tlv(tag_data)
            
            # Extract key fields
            atc = tags.get('9F36', '')
            date = tags.get('9A', '')
            amount = tags.get('9F02', '')
            aip = tags.get('82', '')
            tvr = tags.get('95', '')
            country_code = tags.get('9F1A', '')
            tx_type = tags.get('9C', '')
            
            # Determine if Magstripe or Chip based on AIP
            # AIP byte 1, bit 7 (0x80) indicates SDA supported (Chip)
            # If AIP = '0239' (common value), this is likely chip
            # If AIP = '1800', '2180', '0218' - indicates fallback to magstripe
            is_magstripe = False
            if aip:
                # Magstripe fallback typically has AIP with specific values
                # 1800 is the most common magstripe fallback indicator
                if aip in ['1800', '2180', '0218', '1880']:
                    is_magstripe = True
            
            # Parse amount (last 12 hex digits = 6 bytes = amount in cents)
            amount_value = 0
            if amount and len(amount) >= 12:
                amount_value = int(amount[-12:], 16) / 100
            
            # Parse country code
            country = 'Unknown'
            if country_code and len(country_code) >= 4:
                cc = country_code[:4]
                country = self.COUNTRY_CODES.get(cc, f'Country_{cc}')
            
            # Parse date (YYMMDD)
            tx_date = ''
            if date and len(date) >= 6:
                year = '20' + date[:2]
                month = date[2:4]
                day = date[4:6]
                tx_date = f"{year}-{month}-{day}"
            
            transaction = {
                'cif': cif,
                'pan_masked': pan_masked,
                'atc': atc,
                'date': tx_date,
                'amount': amount_value,
                'country_code': country_code[:4] if country_code else '',
                'country': country,
                'is_magstripe': is_magstripe,
                'aip': aip,
                'transaction_type': tx_type,
                'raw_tags': tags
            }
            
            return transaction
            
        except Exception as e:
            print(f"Error parsing tag 55 data: {e}")
            return None
    
    def _parse_tlv(self, data: str) -> Dict[str, str]:
        """Parse TLV (Tag-Length-Value) encoded data"""
        tags = {}
        i = 0
        
        while i < len(data):
            # Check if we have enough data for a tag
            if i + 2 > len(data):
                break
            
            # Try 2-byte tag first (starts with 9F, 5F, etc)
            first_byte = data[i:i+2]
            if first_byte in ['9F', '5F', 'BF', 'DF']:
                # Two-byte tag
                if i + 4 > len(data):
                    break
                tag = data[i:i+4]
                i += 4
            else:
                # One-byte tag
                tag = data[i:i+2]
                i += 2
            
            # Get length
            if i + 2 > len(data):
                break
            
            length_hex = data[i:i+2]
            try:
                length = int(length_hex, 16)
            except ValueError:
                break
            
            i += 2
            
            # Get value
            value_len = length * 2  # Convert bytes to hex chars
            if i + value_len > len(data):
                # Handle incomplete data
                value = data[i:]
                tags[tag] = value
                break
            else:
                value = data[i:i+value_len]
                tags[tag] = value
                i += value_len
        
        return tags
    
    def _reconstruct_pans(self):
        """Reconstruct complete PANs and compute Luhn check digits"""
        for cif, fragments in self.pan_fragments.items():
            # Combine all fragments to build the complete PAN (minus check digit)
            # Fragments are like: 2295452785590XXX, 2376368841141XXX, etc.
            # We need to extract the digits before XXX
            
            if fragments:
                # Take any fragment (they should all have same digits for a given CIF)
                fragment = list(fragments)[0]
                pan_without_check = fragment.replace('XXX', '')
                
                # Compute Luhn check digit
                check_digit = self._compute_luhn_check_digit(pan_without_check)
                complete_pan = pan_without_check + str(check_digit)
                
                self.complete_pans[cif] = complete_pan
    
    def _compute_luhn_check_digit(self, pan_without_check: str) -> int:
        """Compute Luhn check digit for credit card number"""
        digits = [int(d) for d in pan_without_check]
        
        # Luhn algorithm
        # Start from rightmost digit, double every second digit
        for i in range(len(digits) - 1, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9
        
        total = sum(digits)
        check_digit = (10 - (total % 10)) % 10
        
        return check_digit
    
    def create_tables(self, cursor: sqlite3.Cursor):
        """Create database tables for EMV data"""
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS emv_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cif TEXT NOT NULL,
                pan_masked TEXT,
                pan_complete TEXT,
                atc TEXT,
                date TEXT,
                amount REAL,
                country_code TEXT,
                country TEXT,
                is_magstripe INTEGER,
                aip TEXT,
                transaction_type TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS emv_customers (
                cif TEXT PRIMARY KEY,
                pan_complete TEXT,
                check_digit INTEGER
            )
        ''')
    
    def save_to_db(self, cursor: sqlite3.Cursor, file_path: str):
        """Save parsed EMV data to database"""
        for transaction in self.transactions:
            cif = transaction['cif']
            pan_complete = self.complete_pans.get(cif, '')
            
            cursor.execute('''
                INSERT INTO emv_transactions 
                (cif, pan_masked, pan_complete, atc, date, amount, country_code, 
                 country, is_magstripe, aip, transaction_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cif,
                transaction['pan_masked'],
                pan_complete,
                transaction['atc'],
                transaction['date'],
                transaction['amount'],
                transaction['country_code'],
                transaction['country'],
                1 if transaction['is_magstripe'] else 0,
                transaction['aip'],
                transaction['transaction_type']
            ))
        
        # Save complete PANs
        for cif, pan_complete in self.complete_pans.items():
            check_digit = int(pan_complete[-1]) if pan_complete else 0
            cursor.execute('''
                INSERT OR REPLACE INTO emv_customers (cif, pan_complete, check_digit)
                VALUES (?, ?, ?)
            ''', (cif, pan_complete, check_digit))
    
    def get_queries(self) -> Dict[str, str]:
        """Return available SQL queries for EMV analysis"""
        return {
            'all_transactions': '''
                SELECT cif, pan_masked, date, amount, country, 
                       CASE WHEN is_magstripe = 1 THEN 'Magstripe' ELSE 'Chip' END as type
                FROM emv_transactions
                ORDER BY date, cif
            ''',
            
            'complete_pans': '''
                SELECT cif, pan_complete, check_digit
                FROM emv_customers
                ORDER BY cif
            ''',
            
            'magstripe_transactions': '''
                SELECT cif, pan_masked, date, amount, country
                FROM emv_transactions
                WHERE is_magstripe = 1
                ORDER BY date
            ''',
            
            'transactions_by_customer': '''
                SELECT cif, COUNT(*) as transaction_count,
                       SUM(CASE WHEN is_magstripe = 1 THEN 1 ELSE 0 END) as magstripe_count,
                       SUM(CASE WHEN is_magstripe = 0 THEN 1 ELSE 0 END) as chip_count
                FROM emv_transactions
                GROUP BY cif
                ORDER BY cif
            ''',
            
            'transactions_by_country': '''
                SELECT country, country_code, COUNT(*) as count
                FROM emv_transactions
                WHERE country != 'Unknown'
                GROUP BY country, country_code
                ORDER BY count DESC
            ''',
            
            'high_value_transactions': '''
                SELECT cif, pan_masked, date, amount, country, 
                       CASE WHEN is_magstripe = 1 THEN 'Magstripe' ELSE 'Chip' END as type
                FROM emv_transactions
                WHERE amount > 1000
                ORDER BY amount DESC
            ''',
            
            'customer_summary': '''
                SELECT c.cif, c.pan_complete, c.check_digit,
                       COUNT(t.id) as total_transactions,
                       SUM(CASE WHEN t.is_magstripe = 1 THEN 1 ELSE 0 END) as magstripe_count,
                       SUM(t.amount) as total_amount
                FROM emv_customers c
                LEFT JOIN emv_transactions t ON c.cif = t.cif
                GROUP BY c.cif, c.pan_complete, c.check_digit
                ORDER BY c.cif
            ''',
            
            'fraud_analysis': '''
                SELECT cif, country, COUNT(*) as suspicious_count,
                       GROUP_CONCAT(DISTINCT date) as dates
                FROM emv_transactions
                WHERE country NOT IN ('United States', 'Canada', 'Unknown')
                GROUP BY cif, country
                ORDER BY suspicious_count DESC
            '''
        }


# Required plugin interface
def get_plugin():
    """Return the plugin instance"""
    return EMVPlugin()
