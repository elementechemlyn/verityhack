### Python Example Application
An example application that demonstrate using the Python Verity SDK to build a patient held list of verified Medications

See [Getting Started](../../../docs/getting-started/getting-started.md) guide for a guided tutorial that makes use of this example application.  

## Prerequisites
Install the following items:
* `libindy` -- Install a stable version. Follow the instructions on the 
[indy-sdk Github Project Page](https://github.com/hyperledger/indy-sdk#installing-the-sdk).
* `Ngrok` -- This is a temporary installation to facilitate early experimentation.
* `Python3` -- Follow the instructions on the [Python3 website](https://www.python.org/downloads/)


### Install dependencies
```sh
pip3 install -r requirements.txt
```

### Run example application
```sh
python3 app.py
```

### Use the application
* Visit http://localhost:4000 for the menu page
* Choose "Check in Patient" to create the connection to the patient (Scan QR Code etc)
* Choose "Prescribe Medication" to fill in a form and issue the medication to the patient
* Choose "Review Medications" to request "proof" of medication list and view medications

### TODO
* Choose "Withdraw Medication" to revoke a medication

### Limitations
* The Connect.me app only returns the latest credential to match the proof request rather than the full list of "Medications"