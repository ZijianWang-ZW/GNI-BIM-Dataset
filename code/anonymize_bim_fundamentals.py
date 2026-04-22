import os
import pandas as pd
from pathlib import Path
import ifcopenshell
import re
from multiprocessing import Pool
from tqdm import tqdm
from collections.abc import Iterable
import zipfile


local_path = r"C:\Users\<USER>\Repos\2025_BIMfundamentals-ifc"

new_path = r"C:\Users\<USER>\Repos\2025_BIMfundamentals-ifc_retracted"

mapping_path = r"C:\Users\<USER>\Repos\2025_BIMfundamentals-ifc_mapping.csv"

VERIFICATION_LOG = Path('data/redaction_hits.log') 

def _register_term(terms: set[str], value: str | None) -> None:
    if value is None:
        return
    cleaned = value.strip()
    if cleaned:
        terms.add(cleaned)


def _register_sequence(terms: set[str], values: Iterable[str] | None) -> None:
    if not values:
        return
    for item in values:
        if isinstance(item, str):
            _register_term(terms, item)


def _log_redaction_event(message: str) -> None:
    VERIFICATION_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(VERIFICATION_LOG, 'a') as log_file:
        log_file.write(f"{message}\n")
    print(message)


def _find_term_hits(content_lower: str, terms: set[str]) -> set[str]:
    hits: set[str] = set()
    for term in terms:
        normalized = term.strip()
        if not normalized:
            continue
        lowered = normalized.lower()
        pattern = re.compile(rf'(?<![a-z0-9_]){re.escape(lowered)}(?![a-z0-9_])')
        for match in pattern.finditer(content_lower):
            start, end = match.start(), match.end()
            # Units like .PASCAL.
            if start > 0 and end < len(content_lower) and content_lower[start - 1] == '.' and content_lower[end] == '.':
                continue
            hits.add(normalized)
            break
    return hits


def collect_sensitive_terms(ifc_file) -> set[str]:
    terms: set[str] = set()
    header = ifc_file.header
    file_description = header.file_description
    _register_sequence(terms, file_description.description)
    file_name = header.file_name
    _register_term(terms, file_name.name)
    _register_sequence(terms, file_name.author)
    _register_sequence(terms, file_name.organization)
    _register_term(terms, file_name.preprocessor_version)
    _register_term(terms, file_name.originating_system)

    for person in ifc_file.by_type('IfcPerson'):
        _register_term(terms, getattr(person, 'Identification', None) or getattr(person, 'Id', None))
        _register_term(terms, person.FamilyName)
        _register_term(terms, person.GivenName)
        _register_sequence(terms, person.MiddleNames)
        _register_sequence(terms, person.PrefixTitles)
        _register_sequence(terms, person.SuffixTitles)

    for org in ifc_file.by_type('IfcOrganization'):
        _register_term(terms, org.Name)
        _register_term(terms, org.Description)

    for addr in ifc_file.by_type('IfcPostalAddress'):
        _register_term(terms, addr.InternalLocation)
        _register_sequence(terms, addr.AddressLines)
        _register_term(terms, addr.PostalBox)
        _register_term(terms, addr.Town)
        _register_term(terms, addr.Region)
        _register_term(terms, addr.PostalCode)
        _register_term(terms, addr.Country)

    for tel in ifc_file.by_type('IfcTelecomAddress'):
        _register_sequence(terms, tel.TelephoneNumbers)
        _register_sequence(terms, tel.FacsimileNumbers)
        _register_sequence(terms, tel.ElectronicMailAddresses)
        if hasattr(tel, 'MessagingNumbers'):
            _register_sequence(terms, tel.MessagingNumbers)

    for app in ifc_file.by_type('IfcApplication'):
        _register_term(terms, getattr(app, 'ApplicationFullName', None))
        _register_term(terms, getattr(app, 'ApplicationIdentifier', None))
        _register_term(terms, getattr(app, 'Version', None))
        developer = getattr(app, 'ApplicationDeveloper', None)
        if developer and hasattr(developer, 'Name'):
            _register_term(terms, developer.Name)

    tracked_props = {'author', 'projektnummer', 'project address', 'project name', 'project number', 'client name',
                      'organization name', 'organization description', 'building name',
                      'verfasser email', 'verfasser firma 1', 'verfasser firma 2',
                      'verfasser plz ort', 'verfasser strasse', 'verfasser telefax', 'verfasser telefon'}
    for prop in ifc_file.by_type('IfcPropertySingleValue'):
        name = (prop.Name or '').strip().lower()
        if name in tracked_props:
            nominal = getattr(prop, 'NominalValue', None)
            wrapped = getattr(nominal, 'wrappedValue', None)
            _register_term(terms, wrapped)

    for project in ifc_file.by_type('IfcProject'):
        _register_term(terms, project.Name)
        _register_term(terms, getattr(project, 'LongName', None))
        _register_term(terms, getattr(project, 'Description', None))
        _register_term(terms, getattr(project, 'ObjectType', None))

    for building in ifc_file.by_type('IfcBuilding'):
        _register_term(terms, building.Name)
        _register_term(terms, getattr(building, 'LongName', None))

    return terms


def derive_filename_terms(file_path: str) -> set[str]:
    file_path = file_path.replace('.', '')
    parts = Path(file_path).stem.split('_')
    if not parts:
        return set()

    terms: set[str] = set()
    first_part_tokens = parts[0].replace('-', ' ').split()
    if file_path.startswith('model') or file_path.startswith('assignment'):
        print(file_path)
        raise ValueError(f"File path {file_path} is not valid")
    for token in first_part_tokens:
        _register_term(terms, token)

    if len(parts) > 1:
        _register_term(terms, parts[1])
    else: 
        print(file_path)
        raise ValueError(f"File path {file_path} is not valid")

    return terms



def verify_redaction(new_file_path: str, original_file_path: str, metadata_terms: set[str]) -> dict:
    filename_terms = derive_filename_terms(original_file_path)
    normalized_metadata_terms = {term for term in metadata_terms if term}

    with open(new_file_path, 'r') as file_handle:
        content_lower = file_handle.read().lower()

    report = {'file': new_file_path, 'metadata_hits': set(), 'filename_hits': set()}

    metadata_hits = _find_term_hits(content_lower, normalized_metadata_terms)
    if metadata_hits:
        report['metadata_hits'] = metadata_hits
        _log_redaction_event(
            f"[INFO] Metadata terms still present in {new_file_path}: {', '.join(sorted(metadata_hits))}"
        )

    filename_hits = _find_term_hits(content_lower, filename_terms)
    if filename_hits:
        report['filename_hits'] = filename_hits
        _log_redaction_event(
            f"[FAIL] Filename-derived terms found in {new_file_path}: {', '.join(sorted(filename_hits))}"
        )

    return report


def anonymize_ifc_file(file_tuple):
    model_number, file_path = file_tuple

    if not os.path.exists(new_path):
        os.makedirs(new_path)

    new_file_path = os.path.join(new_path, f'model_{model_number}.ifc')
    # print(f"Mapping: {new_file_path} -> {file_path}")
    # Get the anonymized name from the file path
    anon_id = f'{model_number}'
    
    # Open the IFC file
    ifc_file = ifcopenshell.open(file_path)
    hidden_terms = collect_sensitive_terms(ifc_file)
    # Anonymize file header
    header = ifc_file.header
    file_description = header.file_description
    file_description.description = ('Redacted',)
    file_name = header.file_name

    # Update file header information
    file_name.name = f'{anon_id}'
    file_name.author = (f'User_{anon_id}',)
    file_name.organization = (f'Organization_{anon_id}',)
    file_name.preprocessor_version = 'Redacted'
    file_name.originating_system = 'Redacted'
    file_name.authorization = f'Authorized_{anon_id}'
    # Anonymize IfcPerson entities
    for person in ifc_file.by_type('IfcPerson'):
        if hasattr(person, 'Identification'):
            person.Identification = f'User_{anon_id}'
        elif hasattr(person, 'Id'):
            person.Id = f'User_{anon_id}'
        person.FamilyName = anon_id
        person.GivenName = 'User'
        person.MiddleNames = None
        person.PrefixTitles = None
        person.SuffixTitles = None
        
    # Anonymize IfcOrganization entities
    for org in ifc_file.by_type('IfcOrganization'):
        org.Name = f'Organization_{anon_id}'
        org.Description = None
        
    # Anonymize IfcPostalAddress entities
    for addr in ifc_file.by_type('IfcPostalAddress'):
        addr.Purpose = None
        addr.Description = None
        addr.UserDefinedPurpose = None
        addr.InternalLocation = None
        addr.AddressLines = None
        addr.PostalBox = None
        addr.Town = None
        addr.Region = None
        addr.PostalCode = None
        addr.Country = None
        
    # Anonymize IfcTelecomAddress entities
    for tel in ifc_file.by_type('IfcTelecomAddress'):
        tel.TelephoneNumbers = None
        tel.FacsimileNumbers = None
        tel.ElectronicMailAddresses = (f'{anon_id}@example.com',)
        if hasattr(tel, 'MessagingNumbers'):
            tel.MessagingNumbers = None
        
    # Anonymize IfcApplication entities
    for app in ifc_file.by_type('IfcApplication'):
        # Create or get anonymous organization for ApplicationDeveloper
        anon_org = None
        for org in ifc_file.by_type('IfcOrganization'):
            if org.Name == f'Organization_{anon_id}':
                anon_org = org
                break
        if not anon_org:
            anon_org = ifc_file.create_entity('IfcOrganization', 
                                          Name=f'Organization_{anon_id}')
        
        app.ApplicationDeveloper = anon_org
        # DO Not anonymize version and application full name
        # app.Version = 'Anonymous Version'
        # app.ApplicationFullName = 'Anonymous Application'

    for prop in ifc_file.by_type('IfcPropertySingleValue'):
        name = (prop.Name or '').strip().lower()
        if name == 'author':
            prop.NominalValue = ifc_file.create_entity('IfcText', f'User_{anon_id}')
        elif name == 'projektnummer':
            prop.NominalValue = ifc_file.create_entity('IfcText', f'{model_number}')
        elif name == 'project address':
            prop.NominalValue = ifc_file.create_entity('IfcText', 'Address redacted')
        elif name == 'project name':
            prop.NominalValue = ifc_file.create_entity('IfcText', f'Project_{anon_id}')
        elif name == 'project number':
            prop.NominalValue = ifc_file.create_entity('IfcText', f'PN-{model_number}')
        elif name == 'client name':
            prop.NominalValue = ifc_file.create_entity('IfcText', f'Client_{anon_id}')
        elif name == 'organization name':
            prop.NominalValue = ifc_file.create_entity('IfcText', f'Organization_{anon_id}')
        elif name == 'organization description':
            prop.NominalValue = ifc_file.create_entity('IfcText', 'Redacted')
        elif name == 'building name':
            prop.NominalValue = ifc_file.create_entity('IfcText', f'Building_{anon_id}')
        elif name.startswith('verfasser'):
            prop.NominalValue = ifc_file.create_entity('IfcText', 'Redacted')

    for project in ifc_file.by_type('IfcProject'):
        project.Name = f'Project_{anon_id}'
        project.LongName = f'Anonymous Project {anon_id}'
        project.Description = 'Redacted'
        project.ObjectType = 'AnonymizedSubmission'

    for building in ifc_file.by_type('IfcBuilding'):
        building.Name = f'Building_{anon_id}'
        building.LongName = f'Building_{anon_id}'
    
    # Save to temporary file first
    ifc_file.write(new_file_path)

    report = verify_redaction(new_file_path, Path(file_path).parent.name, hidden_terms)
    return report

def extract_zips(directory):
    """Extract all ZIP files in directory to the same location."""
    directory_path = Path(directory)
    zip_files = list(directory_path.rglob('*.zip')) + list(directory_path.rglob('*.ZIP'))

    if not zip_files:
        return

    print(f"\n📦 Extracting {len(zip_files)} ZIP file(s)...")
    for zf in tqdm(zip_files, desc="Extracting ZIPs"):
        try:
            with zipfile.ZipFile(zf, 'r') as zip_ref:
                zip_ref.extractall(zf.parent)
            print(f"✓ Extracted: {zf.name}")
        except Exception as e:
            print(f"⚠️  Failed to extract {zf.name}: {e}")


def process_directory(directory):
    directory_path = Path(directory)
    ifc_files = sorted(str(path) for path in directory_path.rglob('*.ifc'))
    return [(str(index), file_path) for index, file_path in enumerate(ifc_files)]

if __name__ == '__main__':

    # Check for ZIP files — they need to be extracted first
    zip_files = list(Path(local_path).rglob('*.zip')) + list(Path(local_path).rglob('*.ZIP'))
    if zip_files:
        print(f"\n⚠️  WARNING: Found {len(zip_files)} ZIP file(s) in input directory:")
        for zf in zip_files:
            print(f"   {str(zf)}")
        print("\nZIP files must be extracted to IFC files before running anonymization.")
        print("Please extract all ZIPs and re-run this script.\n")
        raise ValueError(f"Found {len(zip_files)} unprocessed ZIP file(s) in input directory")

    # Only run this part when script is run directly
    all_files = process_directory(local_path)

    if not all_files:
        raise ValueError(f"No IFC files found in {local_path}")

    # Use number of CPU cores for parallel processing
    num_processes = min(os.cpu_count()-1, 64)
    print(f"Starting anonymization using {num_processes} processes")

    # Create process pool and run anonymization with progress bar
    with Pool(processes=num_processes) as pool:
        results = list(tqdm(
            pool.imap(anonymize_ifc_file, all_files),
            total=len(all_files),
            desc="Anonymizing files"
        ))

    mapping_rows = []
    filename_issues = []
    for (model_number, original_path), report in zip(all_files, results):
        new_file_path = os.path.join(new_path, f'model_{model_number}.ifc')
        mapping_rows.append({'new_path': new_file_path, 'original_path': original_path})
        if report['filename_hits']:
            filename_issues.append(report)

    pd.DataFrame(mapping_rows).to_csv(mapping_path, index=False)

    # Print summary
    print(f"\nAnonymization complete!")
    print(f"Processed: {len(results)}")

    if filename_issues:
        print(f"\n{'='*60}")
        print(f"WARNING: {len(filename_issues)} file(s) still contain sensitive filename-derived terms:")
        print(f"{'='*60}")
        for report in filename_issues:
            print(f"  {report['file']}")
            print(f"    Terms found: {', '.join(sorted(report['filename_hits']))}")
        print(f"{'='*60}")