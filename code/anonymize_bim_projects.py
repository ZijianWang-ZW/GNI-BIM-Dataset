import os
import pandas as pd
from pathlib import Path
import ifcopenshell
import re
from multiprocessing import Pool
from tqdm import tqdm
from collections.abc import Iterable
import zipfile


local_path = r"C:\Users\<USER>\Repos\2026_BIMprojects-ifc"

new_path = r"C:\Users\<USER>\Repos\2026_BIMprojects-ifc_retracted"

mapping_path = r"C:\Users\<USER>\Repos\2026_BIMprojects-ifc_mapping.csv"

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


def verify_redaction(new_file_path: str, metadata_terms: set[str]) -> dict:
    """Verify anonymization. No filename-based terms for 2026 dataset."""
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

    return report


def anonymize_ifc_file(file_tuple):
    """Anonymize a single IFC file. file_tuple = (model_id, file_path, file_type)"""
    model_id, file_path, file_type = file_tuple

    if not os.path.exists(new_path):
        os.makedirs(new_path)

    new_file_path = os.path.join(new_path, f'model_{model_id}_{file_type}.ifc')
    anon_id = f'{model_id}'

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
        anon_org = None
        for org in ifc_file.by_type('IfcOrganization'):
            if org.Name == f'Organization_{anon_id}':
                anon_org = org
                break
        if not anon_org:
            anon_org = ifc_file.create_entity('IfcOrganization',
                                          Name=f'Organization_{anon_id}')
        app.ApplicationDeveloper = anon_org

    for prop in ifc_file.by_type('IfcPropertySingleValue'):
        name = (prop.Name or '').strip().lower()
        if name == 'author':
            prop.NominalValue = ifc_file.create_entity('IfcText', f'User_{anon_id}')
        elif name == 'projektnummer':
            prop.NominalValue = ifc_file.create_entity('IfcText', f'{model_id}')
        elif name == 'project address':
            prop.NominalValue = ifc_file.create_entity('IfcText', 'Address redacted')
        elif name == 'project name':
            prop.NominalValue = ifc_file.create_entity('IfcText', f'Project_{anon_id}')
        elif name == 'project number':
            prop.NominalValue = ifc_file.create_entity('IfcText', f'PN-{model_id}')
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

    # Save the anonymized file
    ifc_file.write(new_file_path)

    report = verify_redaction(new_file_path, hidden_terms)
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


def process_projects(directory):
    """Find all project folders and their IFC files (architecture and structure).
    Groups arc and structure files from same folder with same model ID."""
    directory_path = Path(directory)
    project_files = []
    model_id = 0

    # Find all unique project folders that contain IFC files
    project_folders = set()
    for ifc_file in directory_path.rglob('*.ifc'):
        if ifc_file.name in ('architecture.ifc', 'structure.ifc'):
            project_folders.add(ifc_file.parent)

    # Sort folders for consistent ordering
    for folder in sorted(project_folders):
        arc_file = folder / 'architecture.ifc'
        struct_file = folder / 'structure.ifc'

        # Add both files with same model ID if they exist
        if arc_file.exists():
            project_files.append((str(model_id), str(arc_file), 'arc'))
        if struct_file.exists():
            project_files.append((str(model_id), str(struct_file), 'structure'))

        # Increment model ID only after processing a folder pair
        if arc_file.exists() or struct_file.exists():
            model_id += 1

    return project_files


if __name__ == '__main__':

    # Extract any ZIP files first
    extract_zips(local_path)

    # Process all project IFC files
    all_files = process_projects(local_path)

    if not all_files:
        # Check if there are other IFC files with different naming
        all_ifc_files = list(Path(local_path).rglob('*.ifc'))
        if all_ifc_files:
            print(f"\n⚠️  WARNING: No 'architecture.ifc' or 'structure.ifc' files found.")
            print(f"Found {len(all_ifc_files)} IFC file(s) with different naming:")
            for ifc in all_ifc_files[:10]:
                print(f"   {ifc.relative_to(local_path)}")
            if len(all_ifc_files) > 10:
                print(f"   ... and {len(all_ifc_files) - 10} more")
        raise ValueError(f"No IFC files matching expected pattern in {local_path}")

    print(f"\nFound {len(all_files)} IFC file(s) to anonymize")

    # Use number of CPU cores for parallel processing
    num_processes = min(os.cpu_count() - 1, 64)
    print(f"Starting anonymization using {num_processes} processes")

    # Create process pool and run anonymization with progress bar
    with Pool(processes=num_processes) as pool:
        results = list(tqdm(
            pool.imap(anonymize_ifc_file, all_files),
            total=len(all_files),
            desc="Anonymizing files"
        ))

    mapping_rows = []
    metadata_issues = []
    for (model_id, original_path, file_type), report in zip(all_files, results):
        new_file_path = os.path.join(new_path, f'model_{model_id}_{file_type}.ifc')
        mapping_rows.append({
            'new_path': new_file_path,
            'original_path': original_path,
            'file_type': file_type
        })
        if report['metadata_hits']:
            metadata_issues.append(report)

    pd.DataFrame(mapping_rows).to_csv(mapping_path, index=False)

    # Print summary
    print(f"\nAnonymization complete!")
    print(f"Processed: {len(results)}")

    if metadata_issues:
        print(f"\n{'='*60}")
        print(f"INFO: {len(metadata_issues)} file(s) with residual metadata terms:")
        print(f"{'='*60}")
        for report in metadata_issues:
            print(f"  {report['file']}")
            print(f"    Terms found: {', '.join(sorted(report['metadata_hits']))}")
        print(f"{'='*60}")
