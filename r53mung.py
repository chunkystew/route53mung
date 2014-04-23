#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import sys
import os
import os.path
from lxml import etree
import yaml
import requests
import hmac
import hashlib
import base64
# Change this at your hazard...
r53api = "https://route53.amazonaws.com/2013-04-01/"
r53apidoc = "https://route53.amazonaws.com/doc/2013-04-01/"
def printhelp():
	print
	print "Route53Mung revision 23 Apr 2014"
	print "Written by Matthew Saunier"
	print "This code is released under the GPL, version 3 or later (at your option)"
	print
	print "Usage: r53mung [-j <AWS JSON credentials>] [-z <zone name>] [-r -a <record name>]"
	print "               [-t <type>] [-d <value 1> ... <value n>] [-w weight] [-v] [-h]"
	print 
	print "-j: (MANDATORY) Path to your AWS credentials, in JSON format."
	print "-z: DNS zone to modify. if -z is not specified without a zone, all zones will be"
	print "    listed. If no other options are specified, all records in the specified zone"
	print "    will be listed."
	print "-r: The DNS record to remove. Cannot be specified together with -a."
	print "-a: The DNS record to add. Cannot be specified together with -r. This option will"
	print "    overwrite an existing matching record, if any. This must be expressed as a"
	print "    FQDN."
	print "-t: (MANDATORY if -a or -r specified) The type of the record."
	print "-d: (MANDATORY if -a specified) One or more values for the new record."
	print "-l: (MANDATORY if -a specified) The TTL of the new record."
        print "-h: Display this summary."
	print
	print "Zone output format: Name, ID"
	print "Record output format: Name, Type, Value, TTL"
	print
	print "Notes: This tool can only edit basic (RFC 2181) record types. Using this tool to"
	print "       manipulate latency, failover, and alias records may produce unexpected"
	print "       results."
	print
	print "       This tool returns record values exactly as presented by Route 53. Values"
	print "       may include unescaped whitespace."
	print
	sys.exit(255)
def errortest(response):
	if not response.status_code == requests.codes.ok:
		print "ERROR: Route 53 returned HTTP " + str(response.status_code),
		# If there is no message, this will die without printing more text, so the print statement above must emit a properly formatted error.
	try:
		responsexml = etree.fromstring(response.text)
	except Exception:
		# There was no inner message to return, and that's OK.
		sys.exit(1)
	if not response.status_code == requests.codes.ok:
		if not responsexml.find("Message") == None:
			# Print the inner exception.
			print "- " + responsexml.find("Message").text
	# Return the response as XML.
	return responsexml
if len(sys.argv) <= 1:
	printhelp()
input = {}
input["zone"] = ""
input["name"] = ""
input["type"] = ""
input["value"] = set([])
input["ttl"] = ""
input["action"] = "list"
credfile = ""
currentarg = ""
for i in range(1,len(sys.argv)):
	arg = sys.argv[i]
	if re.search(r'(?:^-)(.)', arg):
		currentarg = arg[1]
		if currentarg == "r":
			input["action"] = "remove"
		if currentarg == "a":
			input["action"] = "add"
		if currentarg == "h":
			printhelp()
	else:
		if currentarg == "j":
			credfile = arg
		# -r and -a cannot be specified together? I LIED. The last one entered will take precedence.
		elif currentarg == "r" or currentarg == "a":
			input["name"] = arg.strip(".")
		elif currentarg == "z":
			input["zone"] = arg.strip(".")
		elif currentarg == "t":
			input["type"] = arg
		elif currentarg == "d":
			input["value"].add(arg)
		elif currentarg == "l":
			input["ttl"] = arg
		else:
			print "ERROR: Unable to parse the parameter \"" + arg + "\" at position " + str(i)
			sys.exit(1)
if not credfile:
	print "ERROR: No credential file specified"
	sys.exit(1)
if input["action"] == "remove" and (not input["name"] or not input["type"]):
	print "ERROR: When adding a record, type must be specified"
	sys.exit(1)
if input["action"] == "add" and (not input["name"] or not input["type"] or not input["value"] or not input["ttl"]):
	print "ERROR: When adding a record, type, data, and TTL must be specified"
	sys.exit(1)
try:
	open(credfile, "r")
except:
	print "ERROR: Unable open \"" + credfile + "\" for reading"
	sys.exit(1)
try:
	creds = yaml.load(file(credfile))
except:
	print "ERROR: Unable to decode \"" + credfile + "\" as JSON"
	sys.exit(1)
if not creds['private-key'] or not creds["access-id"]:
        print "ERROR: \"" + credfile + "\" does not contain private-key and access-id"
        sys.exit(1)
# Construct magic security foo
auth = {}
auth["x-amz-date"] = requests.get(r53api + "/date").headers["date"]
reqsig = base64.b64encode(hmac.new(creds["private-key"], auth["x-amz-date"], hashlib.sha256).digest())
auth["X-Amzn-Authorization"] = "AWS3-HTTPS AWSAccessKeyID=" + creds["access-id"] + ",Algorithm=HmacSHA256,Signature=" + reqsig
# Retrieve the list of zones, since it will always be needed. This authenticates against the API as well, so auth errors will get caught here.
zones = {}
truncated = False
nextmarker = ""
# OMG infinite loop. I really whish that Python had a do-while construct.
while True:
	if not truncated:
		response = errortest(requests.get(r53api + "/hostedzone", headers=auth))
	else:
		payload = {}
		payload["marker"] = nextmarker 
		response = errortest(requests.get(r53api + "/hostedzone", headers=auth, params=payload))
	responsens = response.nsmap[None]
	# This should always be present, but if it isn't munging this here prevents breakage
	if responsens:
		responsens = "{" + responsens + "}"
	for child in response:
		if child.tag == responsens + "HostedZones":
			# I could sanity check this, but Amazon would need to change the API for this to break, so...
			for zone in child:
				id = ""
				name = ""
				count = ""
				for element in zone:
					if element.tag == responsens + "Id":
						# Remove leading /hostedzone/
						id = re.search(r'(?:^/hostedzone/)(.*)', element.text).group(1)
					elif element.tag == responsens + "Name":
						# Remove trailing .
						name = re.search(r'(.*)(?:\.$)', element.text).group(1)
					elif element.tag == responsens + "ResourceRecordSetCount":
						count = element.text
				if id and name:
					zones[name] = id, count
		elif child.tag == responsens + "IsTruncated":
			# Convert text to a bool.
			if child.text == "true":
				truncated = True
			else:
				truncated = False
		elif child.tag == responsens + "NextMarker":
			nextmarker = child.text
	if not truncated:
		break
if input["action"] == "list" and not input["zone"]:
	# Print the sorted dictionary and exit.
	iterator = iter(sorted(zones.items()))
	for zone in iterator:
		print zone[0] + " " + zone[1][0] + " " + zone[1][1]
	sys.exit(0)
# Make sure that the zone requested exists.
if not input["zone"] in zones:
	print "ERROR: Couldn't locate the zone " + dnszone + " in this Route 53 account"
	sys.exit(1)
# A list keeps the data in the order that Route 53 returns it in.
records = list([])
truncated = False
nextrecordname = ""
nextrecordtype = ""
while True:
	if not truncated:
		response = errortest(requests.get(r53api + "hostedzone/" + zones[input["zone"]][0] + "/rrset", headers=auth))
	else:
		payload = {}
		payload["name"] = nextrecordname 
		payload["type"] = nextrecordtype 
		response = errortest(requests.get(r53api + "hostedzone/" + zones[input["zone"]][0] + "/rrset", headers=auth, params=payload))
	responsens = response.nsmap[None]
	if responsens:
		responsens = "{" + responsens + "}"
	for child in response:
		if child.tag == responsens + "ResourceRecordSets":
			for recordset in child:
				name = ""
				type = ""
				ttl = ""
				dnsvalues = list([])
				for record in recordset:
					# Leave all of these absolutely verbatim. If a trailing . is missing in an edit request, it will fail.
					if record.tag == responsens + "Name":
						name = record.text.strip(".")
					elif record.tag == responsens + "Type":
						type = record.text
					elif record.tag == responsens + "TTL":
						ttl = record.text
					elif record.tag == responsens + "ResourceRecords":
						for values in record:
							if values.tag == responsens + "ResourceRecord":
								for value in values:
									if value.tag == responsens + "Value":
										# That's a mighty indent.
										dnsvalues.append(value.text)
				if name and type and ttl:
					for dnsvalue in dnsvalues:
						records.append([name, type, dnsvalue, ttl])
		elif child.tag == responsens + "IsTruncated":
			# Convert string to bool. Doing it the other way makes the comparisons look weird.
			if child.text == "true":
				truncated = True
			else:
				truncated = False
		elif child.tag == responsens + "NextRecordName":
			nextrecordname = child.text
		elif child.tag == responsens + "NextRecordType":
			nextrecordtype = child.text
	if not truncated:
		break
if input["action"] == "list":
	# List and terminate.
	for record in records:
		print record[0] + " " + record[1] + " " + record[2] + " " + record[3]
	sys.exit(0)
# Do some confusing regex magic to make sure that we have a FQDN in the specified zone. 
regex = re.compile(r'(.*)(?:.' + input["zone"] + r'$)')
if regex.search(input["name"]):
	input["name"] = regex.match(input["name"]).group(1)
input["name"] = input["name"] + "." + input["zone"]
# Create common elements first.
request = etree.Element("ChangeResourceRecordSetsRequest")
request.set("xmlns", r53apidoc)
changebatch = etree.SubElement(request, "ChangeBatch")
changes = etree.SubElement(changebatch, "Changes")
# You have to destroy before you can create.
targets = list([])
for record in records:
	if record[0] == input["name"] and record[1] == input["type"]:
		# Gather any values that need deletion.
		targets.append(record)
if not targets and input["action"] == "remove":
	print "ERROR: The record " + input["name"] + " could not be located in the zone " + input["zone"]
	sys.exit(1)
if targets:
	change = etree.SubElement(changes, "Change")
	action = etree.SubElement(change, "Action")
	action.text = "DELETE"
	resourcerecordset = etree.SubElement(change, "ResourceRecordSet")
	name = etree.SubElement(resourcerecordset, "Name")
	# Add the trailing dot back in. Amazon doesn't seem to care, but do it anyways for the sake of good form.
	name.text = targets[0][0] + "."
	type = etree.SubElement(resourcerecordset, "Type")
	type.text = targets[0][1]
	ttl = etree.SubElement(resourcerecordset, "TTL")
	ttl.text = targets[0][3]
	resourcerecords = etree.SubElement(resourcerecordset, "ResourceRecords")
	for target in targets:
		resourcerecord = etree.SubElement(resourcerecords, "ResourceRecord")
		value = etree.SubElement(resourcerecord, "Value")
		value.text = target[2]
if not input["action"] == "add":
	requestxml = etree.tostring(request, encoding="utf8")
	response = errortest(requests.post(r53api + "hostedzone/" + zones[input["zone"]][0] + "/rrset", headers=auth, data=requestxml))
	sys.exit(0)
# Construct the create part of the request.
change = etree.SubElement(changes, "Change")
action = etree.SubElement(change, "Action")
action.text = "CREATE"
resourcerecordset = etree.SubElement(change, "ResourceRecordSet")
name = etree.SubElement(resourcerecordset, "Name")
name.text = input["name"] + "."
type = etree.SubElement(resourcerecordset, "Type")
type.text = input["type"]
ttl = etree.SubElement(resourcerecordset, "TTL")
ttl.text = input["ttl"]
resourcerecords = etree.SubElement(resourcerecordset, "ResourceRecords")
for target in input["value"]:
	resourcerecord = etree.SubElement(resourcerecords, "ResourceRecord")
	value = etree.SubElement(resourcerecord, "Value")
	value.text = target
requestxml = etree.tostring(request, encoding="utf8")
response = errortest(requests.post(r53api + "hostedzone/" + zones[input["zone"]][0] + "/rrset", headers=auth, data=requestxml))
sys.exit(0)
