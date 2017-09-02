#!/usr/bin/python

import re
import os 
def ipv4_filter (value, index=0, pattern=None):
    
    ip = value
    if len(ip) < 7:
        return False

    ip_bytes = ip.split('.')
    byte1 = int(ip_bytes[0])
    byte2 = int(ip_bytes[1])
    if ip.startswith('0.'): return False

    if ip.startswith('10.'): return False
    if ip.startswith('100.') and (byte2&192 == 64): return False
    if ip.startswith('127.'): return False
    if ip.startswith('169.254.'): return False
    if ip.startswith('172.') and (byte2&240 == 16): return False
    if ip.startswith('192.0.0.'): return False
    if ip.startswith('192.0.2.'): return False
    if ip.startswith('192.168.'): return False
    if ip.startswith('198.') and (byte2&254 == 18): return False
    if ip.startswith('198.51.100.'): return False
    if ip.startswith('203.0.113.'): return False
    if byte1&240 == 224: return False
    if byte1&240 == 240: return False

    if ip.endswith('.0') or ip.endswith('.255'): return False
    
    return True 
      


def domain(value, index=0, pattern=None):

    domain=value    
    tlds = set((
     'ac',  'ad',  'ae',  'aero',  'af',  'ag',  'ai',  'al',
     'am',  'an',  'ao',  'aq',  'ar',  'arpa',  'as',  'asia',
     'at',  'au',  'aw',  'ax',  'az',  'ba',  'bb',  'bd',
     'be',  'bf',  'bg',  'bh',  'bi',  'bike',  'biz',  'bj',
     'bm',  'bn',  'bo',  'br',  'bs',  'bt',  'bv',  'bw',
     'by',  'bz',  'ca',  'camera',  'cat',  'cc',  'cd',  'cf',
     'cg',  'ch',  'ci',  'ck',  'cl',  'clothing',  'cm',  'cn',
     'co',  'com',  'construction',  'contractors',  'coop',  'cr',  'cu',  'cv',
     'cw',  'cx',  'cy',  'cz',  'de',  'diamonds',  'directory',  'dj',
     'dk',  'dm',  'do',  'dz',  'ec',  'edu',  'ee',  'eg',
     'enterprises',  'equipment',  'er',  'es',  'estate',  'et',  'eu',  'fi',
     'fj',  'fk',  'fm',  'fo',  'fr',  'ga',  'gallery',  'gb',
     'gd',  'ge',  'gf',  'gg',  'gh',  'gi',  'gl',  'gm',
     'gn',  'gov',  'gp',  'gq',  'gr',  'graphics',  'gs',  'gt',
     'gu',  'guru',  'gw',  'gy',  'hk',  'hm',  'hn',  'holdings',
     'hr',  'ht',  'hu',  'id',  'ie',  'il',  'im',  'in',
     'info',  'int',  'io',  'iq',  'ir',  'is',  'it',  'je',
     'jm',  'jo',  'jobs',  'jp',  'ke',  'kg',  'kh',  'ki',
     'kitchen',  'km',  'kn',  'kp',  'kr',  'kw',  'ky',  'kz',
     'la',  'land',  'lb',  'lc',  'li',  'lighting',  'lk',  'lr',
     'ls',  'lt',  'lu',  'lv',  'ly',  'ma',  'mc',  'md',
     'me',  'menu',  'mg',  'mh',  'mil',  'mk',  'ml',  'mm',
     'mn',  'mo',  'mobi',  'mp',  'mq',  'mr',  'ms',  'mt',
     'mu',  'museum',  'mv',  'mw',  'mx',  'my',  'mz',  'na',
     'name',  'nc',  'ne',  'net',  'nf',  'ng',  'ni',  'nl',
     'no',  'np',  'nr',  'nu',  'nz',  'om',  'org',  'pa',
     'pe',  'pf',  'pg',  'ph',  'photography',  'pk',  'pl',  'plumbing',
     'pm',  'pn',  'post',  'pr',  'pro',  'ps',  'pt',  'pw',
     'py',  'qa',  're',  'ro',  'rs',  'ru',  'rw',  'sa',
     'sb',  'sc',  'sd',  'se',  'sexy',  'sg',  'sh',  'si',
     'singles',  'sj',  'sk',  'sl',  'sm',  'sn',  'so',  'sr',
     'st',  'su',  'sv',  'sx',  'sy',  'sz',  'tattoo',  'tc',
     'td',  'technology',  'tel',  'tf',  'tg',  'th',  'tips',  'tj',
     'tk',  'tl',  'tm',  'tn',  'to',  'today', 'top', 'tp',  'tr',
     'travel',  'tt',  'tv',  'tw',  'tz',  'ua',  'ug',  'uk',
     'uno',  'us',  'uy',  'uz',  'va',  'vc',  've',  'ventures',
     'vg',  'vi',  'vn',  'voyage',  'vu',  'wf',  'ws',  'xn--3e0b707e',
     'xn--45brj9c',  'xn--80ao21a',  'xn--80asehdb',  'xn--80aswg',  'xn--90a3ac',
     'xn--clchc0ea0b2g2a9gcd',  'xn--fiqs8s',  'xn--fiqz9s',
     'xn--fpcrj9c3d',  'xn--fzc2c9e2c',  'xn--gecrj9c',  'xn--h2brj9c',
     'xn--j1amh',  'xn--j6w193g',  'xn--kprw13d',  'xn--kpry57d',
     'xn--l1acc',  'xn--lgbbat1ad8j',  'xn--mgb9awbf',  'xn--mgba3a4f16a',
     'xn--mgbaam7a8h',  'xn--mgbayh7gpa',  'xn--mgbbh1a71e',  'xn--mgbc0a9azcg',
     'xn--mgberp4a5d4ar',  'xn--mgbx4cd0ab',  'xn--ngbc5azd',  'xn--o3cw4h',
     'xn--ogbpf8fl',  'xn--p1ai',  'xn--pgbs0dh',  'xn--q9jyb4c',
     'xn--s9brj9c',  'xn--unup4y',  'xn--wgbh1c',  'xn--wgbl6a',
     'xn--xkc2al3hye2a',  'xn--xkc2dl3a5ee0h',  'xn--yfro4i67o',  'xn--ygbi2ammx',
     'xxx',  'ye',  'yt',  'za',  'zm',  'zw',))

    
    tld = domain.rsplit('.', 1)[1].lower()
    if tld not in tlds : return False
    return True


