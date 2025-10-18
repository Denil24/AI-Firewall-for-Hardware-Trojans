AI-Powered Firewall for Hardware Trojan Detection in Digital Circuits
Overview
  This project presents an AI-powered firewall system designed to automatically detect and quarantine hardware Trojan-infected Verilog RTL files in real-time.        Hardware Trojans are malicious modifications inserted into digital circuits that can disrupt functionality or leak sensitive information. This system leverages     machine learning techniques, advanced feature extraction, and a responsive web interface to provide automated Trojan detection and enhanced hardware design         security.

Features
  Real-time monitoring of uploaded Verilog files for Trojan detection

  Automated quarantine of suspected Trojan-infected files

  Feature extraction using Abstract Syntax Trees (AST) and regex pattern matching

  Supervised machine learning classification with high accuracy

  User-friendly React-based frontend for file upload and scan history visualization

  Flask backend API for file processing, inference, and firewall logic

  Detailed logging and audit trail of scanned files and detection outcomes

Technologies Used
  Python (Flask) for backend server, file processing, and ML model integration

  React.js for frontend UI development

  Machine Learning models: Random Forest, Support Vector Machine (SVM)

  Verilog code parsing with AST and regex-based feature extraction

  Watchdog library for real-time file monitoring

  CSV/Database for scan history persistence

Installation
  Clone the repository

  Set up Python environment and install dependencies:

  bash
    pip install -r requirements.txt  
    Install Node.js and npm for frontend dependencies

  Navigate to the frontend folder and run:

  bash
    npm install  
    npm start  
    Run the Flask backend server:

  bash
    python app.py  
  Access the web UI via http://localhost:3000

Usage
  Upload Verilog (.v) files through the web interface to scan for hardware Trojans

  Monitor the scan results in real time, including confidence scores and actions taken

  Review scan history with detailed logs for auditing purposes

  Quarantine folder automatically stores Trojan-infected files preventing further usage

Dataset
  The machine learning models were trained and evaluated on Verilog files sourced from Trust-Hub benchmarks containing both clean and Trojan-inserted samples.

Contributing
  Contributions are welcome to improve detection models, add support for additional hardware description languages, or enhance UI/UX. Please submit pull requests     with clear descriptions.

Contact
  For any queries or support, please contact Denil Jos at denilarakkal@gmail.com.
