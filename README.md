# SecureMail

SecureMail is a large-scale analysis tool for the email security posture of Internet domains.  
Given a set of domains (or strings containing email addresses/URLs), the project runs DNS, SMTP/TLS, and HTTP checks to measure adoption, correctness, and quality of the main email channel protection technologies: SPF, DKIM, DMARC, STARTTLS, MTA-STS, TLS-RPT, and DNSSEC.

## Requirements

- Python `3.12`
- Dependencies listed in [requirements.txt](./requirements.txt)

How to install dependencies:

```bash
pip install -r requirements.txt
```

## Dataset Building (source domains)

Datasets in `data/src/` are generated with [utils/mail/search_domains.py](./utils/mail/search_domains.py).

Main functions:
- `get_domains_ita()`
- `get_domains_usa()`
- `get_domains_uk()`
- `get_domains_de()`

Implemented workflow:
1. Download public sources for each country (URLs are in the code);
2. Normalize input values and filter valid records;
3. Extract domains from emails/URLs/hostnames;
4. Technical domain validation: keep only domains with a valid `MX` record;
5. Export to `data/src/DOMAINS_<COUNTRY>.csv`.

Related files:
- [utils/mail/organizational_domains.py](./utils/mail/organizational_domains.py): organizational domain calculation based on `data/public_suffixes_agg.csv` (used in provider/AS analyses).

The repository also includes some prebuilt datasets used for comparing results:
- `data/similarweb/`
- `data/tranco/`

## Entry Point

The entry point for analysis is [MAIN.py](./MAIN.py):


1. Reads the source CSV;
2. Extracts unique domains;
3. Analyzes each domain;
4. Saves structured outputs in `data/OUT/`.

Run:

```bash
python MAIN.py
```

## Analysis Performed for Each Domain

The following analyses are executed for every domain.

1. **Basic DNS analysis**:
   - Query `MX`, `NS`, `A`, `CNAME`;
   - Minimum DNS reachability check: the domain must have MX and at least one resolved NS.

2. **STARTTLS on MX servers**:
   - SMTP connection to MX servers;
   - Check availability of `STARTTLS` extension;
   - Attempt TLS handshake;
   - Collect and validate the presented certificate;
   - Final status: supported/not supported + errors/warnings.

3. **SPF**;
   - Search for SPF record (`SPF`/`TXT`);
   - Syntactic and semantic validation of the record;
   - Check for multiple records (error);
   - Analyze `include` and `redirect` mechanisms with recursive resolution;
   - Compute policy default qualifier;
   - Detect IP overlap in policies;
   - Report errors when retrieving included sub-policies.

4. **DKIM**:
   - Search for common DKIM selectors (`selector._domainkey.<domain>`);
   - Retrieve `TXT` records and parse policy;
   - Count policies found per domain;
   - Detect errors (invalid records, empty keys) and partial warnings.

5. **DMARC**:
   - Search `_dmarc.<domain>` record (with fallback to organizational domain);
   - Validate uniqueness and correctness of DMARC policy;
   - Extract `p` policy;
   - Validate external report delegation (`rua`, `ruf`) through `<source>._report._dmarc.<report-domain>` records;

6. **MTA-STS**:
   - Check DNS `_mta-sts.<domain>` record;
   - Check policy host reachability `mta-sts.<domain>`;
   - Download policy from `/.well-known/mta-sts.txt`;
   - Validate web server TLS certificate;
   - Parse/validate MTA-STS policy;
   - Check alignment between policy MX patterns and actual MX records;
   - Check presence of at least one aligned MX with a valid certificate.

7. **TLS-RPT**:
   - Check `_smtp._tls.<domain>` record;
   - Validate presence/uniqueness/format.

8. **DNSSEC**:
   - Query `DNSKEY` on the domain;
   - DNSSEC adoption flag based on record presence.

## Output

Main outputs produced in `data/OUT/`:

- `Summary.csv`: per-domain summary (flags, errors, warnings, main policies);
- `DomainStatuses.pkl`: full objects for further analysis;
- `Policies.json`: export of detected policies (SPF, DKIM, DMARC, MTA-STS, TLS-RPT);
- `DNS.json`: dump of collected DNS records;
- `Providers.csv`: provider/infrastructure classification (NS/MX/WEB, INT/EXT);
- `AutonomousSystems.json`: AS details associated with observed hosts and IPs;
- `MXs.csv`: STARTTLS status and certificate metadata for MX servers;
- `DKIM.csv`: DKIM selector/key details and cross-domain reuse;
- `SPF.csv`: SPF policy structure (include/redirect levels, mechanisms, errors);
- `IPs.json`: subnets/IPs shared by many domains with ASN metadata.

## Results Notebook

[results.ipynb](./results.ipynb) contains exploratory analyses and visualizations on files produced by the pipeline (`Summary.csv`, `SPF.csv`, `DKIM.csv`, `Providers.csv`, `IPs.json`, etc.).
