"""
for REPO in $(aws --profile default ecr describe-repositories | awk -F[\":] '/repositoryName/{print $5}'); do
    for IMAGE in $(aws --profile default ecr list-images --repository-name ${REPO} | awk -F\" '/imageDigest/{print $4}' | sort -u); do
            echo "**** Retrieving image scan results for ${REPO}:${IMAGE} ****"
                    aws --profile default ecr describe-image-scan-findings --repository-name ${REPO} --image-id imageDigest=${IMAGE}
                        done
                        done
"""
import boto3
import json
import pprint
import csv
import requests
import shutil
import zipfile

global start_year
start_year = 2002
# url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-" + str(start_year) + ".json.zip"

def search_cache(cve):
    print ("cve is")
    print (cve)
    cve_year = cve[4:8]
    print (cve_year)

# Check year cache file
    d = None
    data = None
    with zipfile.ZipFile("./cache/nvdcve-1.1-" + cve_year + ".json.zip", "r") as z:
        for filename in z.namelist():
            print ("Searching " + filename + " cache for " + cve)
            with z.open(filename) as f:
                data = f.read()
                d = json.loads(data)

    itemnumber = 0
    found = 0
    for sub in d['CVE_Items']:
        itemnumber = itemnumber + 1
        if sub['cve']['CVE_data_meta']['ID'] == cve:
           found = 1
           print ("found it")
           print ("CVE DATA")
           print (sub['cve'])
           print ("CONFIGURATION")
           print (sub['configurations'])
           print ("IMPACT")
           print (sub['impact'])

# Check recent cache
    if found == 0:
        print ("Didnt find it trying recent cache")
    d = None
    data = None
    with zipfile.ZipFile("./cache/nvdcve-1.1-recent.json.zip", "r") as z:
        for filename in z.namelist():
            print ("Searching " + filename + " cache for " + cve)
            with z.open(filename) as f:
                data = f.read()
                d = json.loads(data)

    itemnumber = 0
    found = 0
    for sub in d['CVE_Items']:
        itemnumber = itemnumber + 1
        if sub['cve']['CVE_data_meta']['ID'] == cve:
           found = 1
           print ("found it")
           print ("CVE DATA")
           print (sub['cve'])
           print ("CONFIGURATION")
           print (sub['configurations'])
           print ("IMPACT")
           print (sub['impact'])

# Check modified cache
    if found == 0:
        print ("Didnt find it trying modified cache")
        d = None
    data = None
    with zipfile.ZipFile("./cache/nvdcve-1.1-modified.json.zip", "r") as z:
        for filename in z.namelist():
            print ("Searching " + filename + " cache for " + cve)
            with z.open(filename) as f:
                data = f.read()
                d = json.loads(data)

    itemnumber = 0
    found = 0
    for sub in d['CVE_Items']:
        itemnumber = itemnumber + 1
        if sub['cve']['CVE_data_meta']['ID'] == cve:
           found = 1
           print ("found it")
           print ("CVE DATA")
           print (sub['cve'])
           print ("CONFIGURATION")
           print (sub['configurations'])
           print ("IMPACT")
           print (sub['impact'])

def thescan(theimage,thetag,repo):
    # Save original JSON to file
    scanfile = open("scanfile.txt", "a")
    scanresponse = client.describe_image_scan_findings(repositoryName=repo, imageId={'imageDigest':theimage, 'imageTag':thetag})
    scanfile.write(json.dumps(scanresponse, indent=2, default=str))
    scanfile.close()
    print ("imhere")
    data = scanresponse
    search_cache(str(data['imageScanFindings']['findings'][0]['name']))

def thelist(repo):
    print ("made it in to list\n")
    listfile = open("listfile.txt", "a")
    listfilewriter = csv.writer(listfile)
    imagesresponse = client.list_images(repositoryName=repo)
    try:
        imagecount = 0
        for somethingelse in imagesresponse['imageIds'][0]['imageDigest']:
            listfilewriter.writerow(imagesresponse['imageIds'][imagecount]['imageDigest'] + "\n")
            listfilewriter.writerow(imagesresponse['imageIds'][imagecount]['imageTag'] + "\n")
            listfile.close()

            print (imagesresponse['imageIds'][imagecount]['imageDigest'])
            print (imagesresponse['imageIds'][imagecount]['imageTag'])
            theimage = (imagesresponse['imageIds'][imagecount]['imageDigest'])
            thetag = (imagesresponse['imageIds'][imagecount]['imageTag'])
            thescan(theimage,thetag,repo)
            imagecount = imagecount + 1
    except:
        return

# Download the cache from NVD
def download_file(url):
    local_filename = url.split('/')[-1]
    with requests.get(url, stream=True) as r:
        if r.status_code == 404:
            exit()
        with open("cache/" + local_filename, 'wb') as f:
            shutil.copyfileobj(r.raw, f)
    return local_filename

# Freshen up the cache
try:
    download_file("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip")
    download_file("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip")

    while True:
        url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-" + str(start_year) + ".json.zip"
        download_file(url)
        start_year = start_year + 1
        print ("Download of " + url + " completed")
except:

# Pull ECR registry from AWS
    client = boto3.client('ecr')
    response = client.describe_repositories()
    repositoryfile = open("repositoryfile.txt", "a")
    repositoryfilewriter = csv.writer(repositoryfile)
    count = 0
    for something in response['repositories'][0]['repositoryName']:
        print(response['repositories'][count]['repositoryName'])
        repositoryfilewriter.writerow(response['repositories'][count]['repositoryName'] + "\n")
        repo = response['repositories'][count]['repositoryName']
        regid = response['repositories'][count]['registryId']
        thelist(repo)
        count = count + 1

repositoryfile.close()

