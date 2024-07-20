import json
import logging
from flask import Flask, request, jsonify
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.errors import GvmError
from lxml import etree
import xmltodict

# Initialize Flask app
app = Flask(__name__)
# Configure logging to debug level
logging.basicConfig(level=logging.DEBUG)

# Route to trigger a scan
@app.route('/trigger_scan', methods=['POST'])
def trigger_scan_api():
    """
    API endpoint to trigger a scan.
    Expects JSON payload with 'scan_name' and 'targets'.
    """
    data = request.json  # Get JSON data from request
    scan_name = data.get('scan_name')  # Extract scan name
    targets = data.get('targets')  # Extract targets
    port_list_id = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"  # Default port list ID
    
    # Validate input data
    if not all([scan_name, targets]):
        return jsonify({"error": "scan_name, targets, are required"}), 400
    
    # Trigger scan and return result
    result = trigger_scan(scan_name, targets, port_list_id)
    if "error" in result:
        return jsonify(result), 500
    return jsonify(result)

# Route to get scan results by scan ID
@app.route('/get_results/<scan_id>', methods=['GET'])
def get_results(scan_id):
    """
    API endpoint to get scan results.
    Expects scan ID as URL parameter.
    """
    results = retrieve_results(scan_id)  # Retrieve results
    return jsonify(results)

# Function to delete target if it exists
def delete_target_if_exists(gmp, target_name):
    """
    Delete target if it exists.
    
    Parameters:
        gmp: Authenticated GMP object
        target_name: Name of the target to delete
    
    Returns:
        True if target was deleted, False otherwise
    """
    try:
        targets_resp = gmp.get_targets()  # Get list of targets
        targets = targets_resp.findall('target')
        
        # Iterate through targets and delete if match found
        for target in targets:
            if target.find('name').text == target_name:
                target_id = target.get('id')
                gmp.delete_target(target_id=target_id)
                logging.debug(f"Deleted existing target: {target_name} with ID: {target_id}")
                return True
        return False
    except GvmError as e:
        logging.error(f"Error deleting target: {str(e)}")
        return False

# Function to get default config ID
def get_default_config_id(gmp):
    """
    Get the default configuration ID.
    
    Parameters:
        gmp: Authenticated GMP object
    
    Returns:
        Default configuration ID
    
    Raises:
        ValueError: If default configuration is not found
    """
    configs = gmp.get_configs()  # Get list of configs
    for config in configs.findall('config'):
        if config.find('name').text == 'Full and fast':
            return config.get('id')
    raise ValueError('Default config "Full and fast" not found')

# Function to get default scanner ID
def get_default_scanner_id(gmp):
    """
    Get the default scanner ID.
    
    Parameters:
        gmp: Authenticated GMP object
    
    Returns:
        Default scanner ID
    
    Raises:
        ValueError: If default scanner is not found
    """
    scanners = gmp.get_scanners()  # Get list of scanners
    for scanner in scanners.findall('scanner'):
        if scanner.find('name').text == 'OpenVAS Default':
            return scanner.get('id')
    raise ValueError('Default scanner "OpenVAS Default" not found')

# Function to trigger a scan
def trigger_scan(scan_name, targets, port_list_id):
    """
    Trigger a scan with the given parameters.
    
    Parameters:
        scan_name: Name of the scan
        targets: List of targets
        port_list_id: Port list ID
    
    Returns:
        Dictionary containing scan details or error message
    """
    connection = UnixSocketConnection(path='/var/run/gvmd.sock')
    transform = EtreeTransform()

    try:
        with Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(username='admin', password='admin')  # Authenticate
            
            delete_target_if_exists(gmp, scan_name)  # Delete existing target if exists
            target_resp = gmp.create_target(name=scan_name, hosts=targets, port_list_id=port_list_id)  # Create new target
            target_id = target_resp.find('.//id').text if target_resp.find('.//id') is not None else target_resp.get('id')

            config_id = get_default_config_id(gmp)  # Get default config ID
            scanner_id = get_default_scanner_id(gmp)  # Get default scanner ID

            task_resp = gmp.create_task(name=scan_name, config_id=config_id, target_id=target_id, scanner_id=scanner_id)  # Create new task
            task_id = task_resp.find('.//id').text if task_resp.find('.//id') is not None else task_resp.get('id')

            start_task_resp = gmp.start_task(task_id)  # Start the task
            scan_id = start_task_resp.find('.//report_id').text if start_task_resp.find('.//report_id') is not None else start_task_resp.get('id')

            return {"message": "Scan started", "scan_name": scan_name, "targets": targets, "scan_id": scan_id}
    except GvmError as e:
        return {"error": str(e)}
    finally:
        connection.disconnect()

# Function to retrieve scan results
def retrieve_results(scan_id):
    """
    Retrieve scan results for the given scan ID.
    
    Parameters:
        scan_id: ID of the scan
    
    Returns:
        Dictionary containing scan results or error message
    """
    connection = UnixSocketConnection(path='/var/run/gvmd.sock')
    transform = EtreeTransform()

    try:
        with Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(username='admin', password='admin')  # Authenticate

            filter_str = 'levels=hml rows=100 min_qod=70 first=1 sort-reverse=severity'
            report_resp = gmp.get_report(report_id=scan_id, details=1, filter=filter_str)  # Get report
            report_str = etree.tostring(report_resp, pretty_print=True).decode()
            report_dict = xmltodict.parse(report_str)
            
            scan_name = report_dict.get("get_reports_response", {}).get("report", {}).get("task", {}).get("name", "N/A")
            targets = list(set(result['host']['#text'] for result in report_dict.get("get_reports_response", {}).get("report", {}).get("report", {}).get("results", {}).get("result", [])))

            results = process_report(report_dict, scan_name, targets)  # Process report

            return results
    except GvmError as e:
        return {"error": str(e)}
    finally:
        connection.disconnect()

# Function to process the report data
def process_report(data, scan_name, targets):
    """
    Process the report data and extract detailed and summary results.
    
    Parameters:
        data: Report data in dictionary format
        scan_name: Name of the scan
        targets: List of targets
    
    Returns:
        Dictionary containing detailed and summary results
    """
    detailed_results = []
    summary_results = []
    
    try:
        results = data["get_reports_response"]["report"]["report"]["results"]["result"]
    except KeyError as e:
        logging.error(f"Key error: {e}")
        return None

    for result in results:
        endpoint = result['host']['#text']
        nvt = result['nvt']
        
        cve = 'N/A'
        refs = nvt.get('refs', {}).get('ref', [])
        if not isinstance(refs, list):
            refs = [refs]
        for ref in refs:
            if ref.get('@type') == 'cve':
                cve = ref.get('@id', 'N/A')
                break
        
        score = nvt.get('cvss_base', 'N/A')
        severity_value = nvt['severities']['severity']['value'] if 'severities' in nvt and 'severity' in nvt['severities'] and 'value' in nvt['severities']['severity'] else ''
        vector_parts = severity_value.split('/')[1:] if severity_value else []
        av, ac, pr, ui, s, c, i, a = (vector_parts + ['N/A'] * 8)[:8]
        
        av = av.split(':')[1] if ':' in av else av
        ac = ac.split(':')[1] if ':' in ac else ac
        pr = pr.split(':')[1] if ':' in pr else pr
        ui = ui.split(':')[1] if ':' in ui else ui
        s = s.split(':')[1] if ':' in s else s
        c = c.split(':')[1] if ':' in c else c
        i = i.split(':')[1] if ':' in i else i
        a = a.split(':')[1] if ':' in a else a

        detailed_results.append({
            "id": result['@id'],
            "name": result['name'],
            "score": nvt['cvss_base'],
            "creation_time": result['creation_time'],
            "modification_time": result['modification_time']
        })

        summary_results.append({
            "Endpoint": endpoint,
            "CVE": cve,
            "Score": score,
            "AV": av,
            "AC": ac,
            "PR": pr,
            "UI": ui,
            "S": s,
            "C": c,
            "I": i,
            "A": a
        })

    return { "scan_name": scan_name, "targets": targets, "result_details": detailed_results, "result_summary": summary_results}

# Run Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
