
# Assignment on vulnerability assessment - Unige

This repository contains a Flask-based web application for managing OpenVAS (Greenbone Vulnerability Management) scans. The API allows users to trigger scans, retrieve scan results.

Also you can see thses videos to know how to run or config the project :

Execution Video : https://youtu.be/EZFYuDr0T0Q

First Config : https://youtu.be/34Cx398p-M8

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Greenbone Security Assistant](#greenbone-security-assistant)
- [Contributing](#contributing)
- [License](#license)

## Installation

To run this application, you need to have Python and OpenVAS installed on your system. Follow the steps below to set up the application:

1. **Clone the repository:**

   ```sh
   git clone https://github.com/PeimanAtaei/greenbone_project.git
   cd greenbone_project
   ```


## Usage

You can run the application using Docker. Follow the steps below to build and run the Docker container:

1. **Build and run the Docker container:**

   ```sh
   docker-compose up --build -d
   ```

This will build the Docker image and run the container in detached mode. The application will be accessible at `http://localhost:5000`.


## Greenbone Security Assistant

You can also manage scans and view results through the Greenbone Security Assistant web interface. The interface is accessible at [http://127.0.0.1:9392/login](http://127.0.0.1:9392/login).

- **Username:** admin
- **Password:** admin

## API Endpoints

### Trigger Scan

- **URL:** `/trigger_scan`
- **Method:** `POST`
- **Description:** Triggers a new scan.
- **Request Body:**
  ```json
  {
    "scan_name": "example_scan",
    "targets": "192.168.1.1"
  }
  ```
- **Response:**
  ```json
  {
    "message": "Scan started",
    "scan_name": "example_scan",
    "targets": "192.168.1.1",
    "scan_id": "scan_id_here"
  }
  ```

### Get Results

- **URL:** `/get_results/<scan_id>`
- **Method:** `GET`
- **Description:** Retrieves the results of a scan by scan ID.
- **Response:**
  ```json
  {
    "scan_name": "example_scan",
    "targets": ["192.168.1.1"],
    "result_details": [],
    "result_summary": []
  }
  ```

## cURL Command Line Usage

You can interact with the API using the `curl` command line tool. Below are examples of how to use `curl` for each endpoint:

### Trigger Scan

```sh
curl -X POST http://localhost:5000/trigger_scan -H "Content-Type: application/json" -d '{
  "scan_name": "example_scan",
  "targets": "192.168.1.1"
}'
```

### Get Results

```sh
curl -X GET http://localhost:5000/get_results/scan_id_here
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any changes.

1. Fork the repository.
2. Create a new branch: `git checkout -b feature-branch`
3. Make your changes and commit them: `git commit -m 'Add new feature'`
4. Push to the branch: `git push origin feature-branch`
5. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
