AWS ECR NVD Enricher

A Python utility that retrieves vulnerability scan findings from AWS Elastic Container Registry (ECR) and enriches them with additional vulnerability metadata from the National Vulnerability Database (NVD).

Overview

AWS ECR image scanning identifies known vulnerabilities in container images and provides associated vulnerability information, including CVE identifiers and CVSS severity scores.

This tool extends that information by looking up identified CVEs in the NVD and retrieving additional vulnerability details, including CVSS v3 scoring information where available.

The goal is to provide more comprehensive vulnerability information than the ECR scan results alone, making it easier to assess, prioritize, and investigate vulnerabilities within container images.

Key Features
Retrieves repositories from an AWS ECR registry.
Enumerates container images within each repository.
Retrieves existing ECR image vulnerability scan findings.
Identifies CVEs reported by ECR.
Looks up CVEs in locally cached NVD vulnerability databases.
Retrieves additional CVE metadata, including CVSS information.
Stores original ECR scan responses for further analysis.
NVD Data Caching

To minimize repeated requests to the NVD and reduce bandwidth consumption, the tool maintains a local cache of NVD vulnerability data.

The initial setup downloads historical NVD vulnerability feeds, along with the recent and modified vulnerability feeds.

The downloaded feeds are retained as ZIP archives to reduce disk space consumption.

Once downloaded, CVE lookups are performed locally against the cached JSON data rather than requiring an individual NVD API request for every vulnerability.

This approach reduces network traffic and improves lookup performance.

Note: This implementation uses the legacy NVD CVE 1.1 JSON feed format. The NVD has since introduced newer data formats and APIs.

Requirements
Python 3
AWS CLI (for AWS credential configuration)
An AWS account with access to Amazon ECR.
Appropriate IAM permissions to list repositories, enumerate images, and retrieve image scan findings.
Network connectivity to download NVD vulnerability feeds.
Installation

Clone the repository:

bash
git clone <repository-url>
cd <repository-directory>


Install the required Python dependencies:

bash
pip3 install -r requirements.txt

AWS Configuration

Configure your AWS credentials before running the script:

bash
aws configure --profile default


The AWS identity must have the following permissions:

ecr:DescribeRepositories
ecr:ListImages
ecr:DescribeImageScanFindings

The script uses the default AWS credential chain through Boto3. Ensure the configured credentials have access to the intended AWS account and region.

Usage

Run the script:

bash
python3 aws_ecr_nvd_enrich.py


The script will:

Download the NVD recent and modified vulnerability feeds.
Download historical NVD vulnerability feeds when needed.
Connect to AWS ECR.
Retrieve available ECR repositories.
Enumerate container images in each repository.
Retrieve vulnerability scan findings for each image.
Look up identified CVEs in the local NVD cache.
Save scan information and repository/image details to local files.
Output Files

The script generates the following files:

File	Description
repositoryfile.txt	List of ECR repositories retrieved from AWS.
listfile.txt	Image digests and tags retrieved from ECR.
scanfile.txt	Original ECR vulnerability scan responses in JSON format.
cache/	Compressed NVD vulnerability feed archives used for local CVE lookups.

The output files are created in the working directory.

Limitations
The script relies on the legacy NVD CVE 1.1 JSON feeds.
CVE enrichment depends on the availability of matching records in the local NVD cache.
Only the first vulnerability finding is currently processed for each image.
ECR scan results must be available before enrichment can take place.
Large ECR registries may require additional pagination handling.
The current implementation does not provide a consolidated CSV vulnerability report.
Future Improvements

