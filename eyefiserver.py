#!/usr/bin/env python3

"""
* Copyright (c) 2009, Jeffrey Tchang
* Additional *pike *brettneese
* All rights reserved.
*
*
* THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import binascii
import cgi
import errno
import hashlib
import http.client
import io
import logging.handlers
import math
import os
import random
import select
import socket
import socketserver
import sys
import tarfile
import tempfile
import time
import traceback
import xml.dom.minidom
import xml.sax
from datetime import datetime
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from xml.sax.handler import ContentHandler

"""
General architecture notes


This is a standalone Eye-Fi Server that is designed to take the place of the Eye-Fi Manager.


Starting this server creates a listener on port 59278. I use the BaseHTTPServer class included
with Python. I look for specific POST/GET request URLs and execute functions based on those
URLs.




"""

# Create the main logger
eyefi_logger = logging.Logger("eyefi_logger", logging.DEBUG)
# TODO: set logging level with env variable

# Create two handlers. One to print to the log and one to print to the console
consoleHandler = logging.StreamHandler(sys.stdout)

# Set how both handlers will print the pretty log events
eyeFiLoggingFormat = logging.Formatter("[%(asctime)s][%(funcName)s] - %(message)s", '%m/%d/%y %I:%M%p')
consoleHandler.setFormatter(eyeFiLoggingFormat)

# Append both handlers to the main Eye Fi Server logger
eyefi_logger.addHandler(consoleHandler)


# Eye Fi XML SAX ContentHandler
class EyeFiContentHandler(ContentHandler):
    # These are the element names that I want to parse out of the XML
    element_names_to_extract = ["macaddress", "cnonce", "transfermode", "transfermodetimestamp", "fileid", "filename",
                                "filesize", "filesignature"]

    # For each of the element names I create a dictionary with the value to False
    elements_to_extract = {}

    # Where to put the extracted values
    extracted_elements = {}

    def __init__(self):
        ContentHandler.__init__(self)
        self.extracted_elements = {}

        for element_name in self.element_names_to_extract:
            self.elements_to_extract[element_name] = False

    def startElement(self, name, attributes):
        # If the name of the element is a key in the dictionary elements_to_extract
        # set the value to True
        eyefi_logger.debug("startElement: " + name)
        if name in self.elements_to_extract:
            self.elements_to_extract[name] = True
            eyefi_logger.debug("Found element: " + name)

    def endElement(self, name):
        # If the name of the element is a key in the dictionary elements_to_extract
        # set the value to False
        if name in self.elements_to_extract:
            self.elements_to_extract[name] = False

    def characters(self, content):
        for element_name in self.elements_to_extract:
            if self.elements_to_extract[element_name]:
                self.extracted_elements[element_name] = content

# Implements an EyeFi server
class EyeFiServer(socketserver.ThreadingMixIn, HTTPServer):

    def serve_forever(self, **kwargs):
        while True:
            try:
                self.handle_request()
            except select.error as e:
                if e.args[0] != errno.EINTR:
                    raise e

    def server_bind(self):
        HTTPServer.server_bind(self)
        self.socket.settimeout(None)

    def get_request(self):
        try:
            connection, address = self.socket.accept()
            eyefi_logger.debug("Incoming connection from client %s" % address[0])

            connection.settimeout(None)
            eyefi_logger.info("Request received from %s:%s" % address)
            return connection, address

        except socket.timeout:
            self.socket.close()
            pass


# This class is responsible for handling HTTP requests passed to it.
# It implements the two most common HTTP methods, do_GET() and do_post()

class EyeFiRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    sys_version = ""
    server_version = "Eye-Fi Agent/2.0.4.0 (Windows XP SP2)"

    def do_QUIT(self):
        eyefi_logger.debug("Got StopServer request .. stopping server")
        self.send_response(200)
        self.end_headers()
        self.server.stop()

    def do_GET(self):
        try:
            eyefi_logger.debug(self.command + " " + self.path + " " + self.request_version)

            eyefi_logger.debug("Headers received in GET request:")
            for headerName in self.headers:
                headerValues = self.headers.get_all(headerName)
                if headerValues:
                    for headerValue in headerValues:
                        eyefi_logger.debug(headerName + ": " + headerValue)

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            # I should be sending a Content-Length header with HTTP/1.1 but I am being lazy
            # self.send_header('Content-length', '123')
            self.end_headers()
            self.wfile.write(str(self.client_address).encode('utf-8'))
            self.wfile.write(str(self.headers).encode('utf-8'))
        except:
            eyefi_logger.error("Got an an exception:")
            eyefi_logger.error(traceback.format_exc())
            raise

    def do_POST(self):
        try:
            eyefi_logger.debug(self.command + " " + self.path + " " + self.request_version)

            soap_action = ""
            content_length = 0

            # Get headers
            eyefi_logger.debug("Headers received in POST request:")
            soap_action = self.headers.get('SOAPAction', '')
            content_length = int(self.headers.get('Content-Length', 0))
            for headerName in self.headers:
                headerValues = self.headers.get_all(headerName)
                if headerValues:
                    for headerValue in headerValues:
                        eyefi_logger.debug(headerName + ": " + headerValue)

            # Read content_length bytes worth of data
            eyefi_logger.debug("Attempting to read " + str(content_length) + " bytes of data")
            post_data = self.rfile.read(content_length)
            eyefi_logger.debug("Finished reading " + str(content_length) + " bytes of data")

            # Perform action based on path and soap_action
            # A soap_action of StartSession indicates the beginning of an EyeFi
            # authentication request
            if (self.path == "/api/soap/eyefilm/v1") and (soap_action == "\"urn:StartSession\""):
                eyefi_logger.debug("Got StartSession request")
                response = self.start_session(post_data)
                content_length = len(response)

                eyefi_logger.debug("StartSession response: " + str(response))

                self.send_response(200)
                self.send_header('Date', self.date_time_string())
                self.send_header('Pragma', 'no-cache')
                self.send_header('Server', 'Eye-Fi Agent/2.0.4.0 (Windows XP SP2)')
                self.send_header('Content-Type', 'text/xml; charset="utf-8"')
                self.send_header('Content-Length', str(content_length))
                self.end_headers()

                self.wfile.write(response)
                self.wfile.flush()
                self.handle_one_request()

            # GetPhotoStatus allows the card to query if a photo has been uploaded
            # to the server yet
            elif (self.path == "/api/soap/eyefilm/v1") and (soap_action == "\"urn:GetPhotoStatus\""):
                eyefi_logger.debug("Got GetPhotoStatus request")

                response = self.get_photo_status(post_data)
                content_length = len(response)

                eyefi_logger.debug("GetPhotoStatus response: " + str(response))

                self.send_response(200)
                self.send_header('Date', self.date_time_string())
                self.send_header('Pragma', 'no-cache')
                self.send_header('Server', 'Eye-Fi Agent/2.0.4.0 (Windows XP SP2)')
                self.send_header('Content-Type', 'text/xml; charset="utf-8"')
                self.send_header('Content-Length', str(content_length))
                self.end_headers()

                self.wfile.write(response)
                self.wfile.flush()

            # If the URL is upload and there is no soap_action the card is ready to send a picture to me
            elif (self.path == "/api/soap/eyefilm/v1/upload") and (soap_action == ""):
                eyefi_logger.debug("Got upload request")
                response = self.upload_photo(post_data)
                content_length = len(response)

                eyefi_logger.debug("Upload response: " + str(response))

                self.send_response(200)
                self.send_header('Date', self.date_time_string())
                self.send_header('Pragma', 'no-cache')
                self.send_header('Server', 'Eye-Fi Agent/2.0.4.0 (Windows XP SP2)')
                self.send_header('Content-Type', 'text/xml; charset="utf-8"')
                self.send_header('Content-Length', str(content_length))
                self.end_headers()

                self.wfile.write(response)
                self.wfile.flush()

            # If the URL is upload and soap_action is MarkLastPhotoInRoll
            elif (self.path == "/api/soap/eyefilm/v1") and (soap_action == "\"urn:MarkLastPhotoInRoll\""):
                eyefi_logger.debug("Got MarkLastPhotoInRoll request")
                response = self.mark_last_photo_in_roll()
                content_length = len(response)

                eyefi_logger.debug("MarkLastPhotoInRoll response: " + str(response))
                self.send_response(200)
                self.send_header('Date', self.date_time_string())
                self.send_header('Pragma', 'no-cache')
                self.send_header('Server', 'Eye-Fi Agent/2.0.4.0 (Windows XP SP2)')
                self.send_header('Content-Type', 'text/xml; charset="utf-8"')
                self.send_header('Content-Length', str(content_length))
                self.send_header('Connection', 'Close')
                self.end_headers()

                self.wfile.write(response)
                self.wfile.flush()

                eyefi_logger.debug("Connection closed.")
        except:
            eyefi_logger.error("Got an an exception:")
            eyefi_logger.error(traceback.format_exc())
            raise

    # Handles MarkLastPhotoInRoll action
    @staticmethod
    def mark_last_photo_in_roll():
        # Create the XML document to send back
        doc = xml.dom.minidom.Document()

        soap_element = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "SOAP-ENV:Envelope")
        soap_element.setAttribute("xmlns:SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/")
        soap_body_element = doc.createElement("SOAP-ENV:Body")

        mark_last_photo_in_roll_response_element = doc.createElement("MarkLastPhotoInRollResponse")

        soap_body_element.appendChild(mark_last_photo_in_roll_response_element)
        soap_element.appendChild(soap_body_element)
        doc.appendChild(soap_element)

        return doc.toxml(encoding="UTF-8")

    # Handles receiving the actual photograph from the card.
    # post_data will most likely contain multipart binary post data that needs to be parsed
    def upload_photo(self, post_data):

        # Take the post_data bytes and work with it as if it were a file object
        post_data_in_memory_file = io.BytesIO(post_data)

        # Get the content-type header which looks something like this
        # content-type: multipart/form-data; boundary=---------------------------02468ace13579bdfcafebabef00d
        content_type_header = self.headers.get('Content-Type')
        eyefi_logger.debug(content_type_header)

        # Extract the boundary parameter in the content-type header
        header_parameters = content_type_header.split(";")
        eyefi_logger.debug(header_parameters)

        boundary = None
        for param in header_parameters:
            if 'boundary=' in param:
                boundary = param.split('=')[1].strip()
                break

        if boundary is None:
            eyefi_logger.error("No boundary found in Content-Type header")
            return b''

        eyefi_logger.debug("Extracted boundary: " + boundary)

        # boundary needs to be bytes for cgi.parse_multipart when fp is bytes
        boundary_bytes = boundary.encode('utf-8')

        # Parse the multipart/form-data
        pdict = {'boundary': boundary_bytes}
        form = cgi.parse_multipart(post_data_in_memory_file, pdict)
        eyefi_logger.debug("Available multipart/form-data: " + str(form))


        # Parse the SOAPENVELOPE using the EyeFiContentHandler()
        soap_envelope = form.get('SOAPENVELOPE', [None])[0]
        if soap_envelope is None:
            eyefi_logger.error("SOAPENVELOPE not found in form data")
            return b''
        eyefi_logger.debug("SOAPENVELOPE: " + soap_envelope)
        handler = EyeFiContentHandler()
        xml.sax.parseString(soap_envelope, handler)

        file = form.get('FILENAME', [None])[0]

        eyefi_logger.debug("Extracted elements: " + str(handler.extracted_elements))

        image_tarfile_name = handler.extracted_elements["filename"]

        geotag_enable = int(self.server.config['geotag_enable'])
        geotag_accuracy = int(self.server.config['geotag_accuracy'])

        image_tar_path = os.path.join(tempfile.gettempdir(), image_tarfile_name)
        eyefi_logger.debug("Generated path " + image_tar_path)

        file_handle = open(image_tar_path, 'wb')
        eyefi_logger.debug("Opened file " + image_tar_path + " for binary writing")
        file_handle.write(file)
        eyefi_logger.debug("Wrote file " + image_tar_path)

        file_handle.close()
        eyefi_logger.debug("Closed file " + image_tar_path)

        eyefi_logger.debug("Extracting TAR file " + image_tar_path)
        try:
            image_tarfile = tarfile.open(image_tar_path)
        except tarfile.ReadError:
            eyefi_logger.error("Failed to open %s" % image_tar_path)
            raise

        for member in image_tarfile.getmembers():
            # If timezone is a daylight savings timezone, and we are
            # currently in daylight savings time, then use the alt zone
            if time.daylight != 0 and time.localtime().tm_isdst != 0:
                time_offset = time.altzone
            else:
                time_offset = time.timezone
            timezone = time_offset / 60 / 60 * -1
            image_date = datetime.fromtimestamp(member.mtime) - timedelta(hours=timezone)
            upload_dir = image_date.strftime(self.server.config['upload_dir'])
            eyefi_logger.debug("Creating folder " + upload_dir)
            if not os.path.isdir(upload_dir):
                os.makedirs(upload_dir)

            image_tarfile.extract(member, upload_dir)
            image_path = os.path.join(upload_dir, member.name)
            eyefi_logger.debug("image_path " + image_path)
            os.utime(image_path, (member.mtime + time_offset, member.mtime + time_offset))

            if geotag_enable > 0 and member.name.lower().endswith(".log"):
                eyefi_logger.debug("Processing LOG file " + image_path)
                try:
                    image_name = member.name[:-4]
                    shot_time, aps = list(self.parse_log(image_path, image_name))
                    aps = self.get_photo_aps(shot_time, aps)
                    loc = self.get_location(aps)
                    if loc['status'] == 'OK' and float(loc['accuracy']) <= geotag_accuracy:
                        xmp_name = image_name + ".xmp"
                        xmp_path = os.path.join(upload_dir, xmp_name)
                        eyefi_logger.debug("Writing XMP file " + xmp_path)
                        self.write_xmp(xmp_path, float(loc['location']['lat']), float(loc['location']['lng']))
                except:
                    eyefi_logger.error("Error processing LOG file " + image_path)

        eyefi_logger.debug("Closing TAR file " + image_tar_path)
        image_tarfile.close()

        eyefi_logger.debug("Deleting TAR file " + image_tar_path)
        os.remove(image_tar_path)

        # Create the XML document to send back
        doc = xml.dom.minidom.Document()

        soap_element = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "SOAP-ENV:Envelope")
        soap_element.setAttribute("xmlns:SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/")
        soap_body_element = doc.createElement("SOAP-ENV:Body")

        upload_photo_response_element = doc.createElement("UploadPhotoResponse")
        success_element = doc.createElement("success")
        success_element_text = doc.createTextNode("true")

        success_element.appendChild(success_element_text)
        upload_photo_response_element.appendChild(success_element)

        soap_body_element.appendChild(upload_photo_response_element)
        soap_element.appendChild(soap_body_element)
        doc.appendChild(soap_element)

        return doc.toxml(encoding="UTF-8")

    @staticmethod
    def parse_log(logfile, filename):
        shot_time = 0
        aps = {}
        for line in open(logfile):
            timer, timestamp, act = line.strip().split(",", 2)
            act = act.split(",")
            act, args = act[0], act[1:]
            if act in ("AP", "NEWAP"):
                aps.setdefault(args[0], []).append({"time": int(timer), "pwr": int(args[1])})
            elif act == "NEWPHOTO":
                if filename == args[0]:
                    shot_time = int(timer)
            elif act == "POWERON":
                if shot_time > 0:
                    return shot_time, aps
                shot_time = 0
                aps = {}
        if shot_time > 0:
            return shot_time, aps

    def get_photo_aps(self, timer, aps):
        geotag_lag = int(self.server.config['geotag_lag'])
        new_aps = []
        for mac in aps:
            lag = min([(abs(ap["time"] - timer), ap["pwr"]) for ap in aps[mac]], key=lambda a: a[0])
            if lag[0] <= geotag_lag:
                new_aps.append({"mac": mac, "pwr": lag[1]})
        return new_aps

    @staticmethod
    def get_location(aps):
        try:
            # TODO: fix google map API (missing auth key?)
            geo_url = 'maps.googleapis.com'
            headers = {"Host": geo_url}
            params = "?browser=none&sensor=false"
            for ap in aps:
                params += '&wifi=mac:' + '-'.join([ap['mac'][2 * d:2 * d + 2] for d in range(6)]) + '|ss:' + str(
                    int(math.log10(ap['pwr'] / 100.0) * 10 - 50))
            conn = http.client.HTTPSConnection(geo_url)
            conn.request("GET", "/maps/api/browserlocation/json" + params, "", headers)
            resp = conn.getresponse()
            result = resp.read().decode('utf-8')
            conn.close()
        except:
            eyefi_logger.debug("Error connecting to geolocation service")
            return None
        try:
            import json
            return json.loads(result)
        except:
            try:
                import re
                result = result.replace("\n", " ")
                loc = dict()
                loc['location'] = {}
                loc['location']['lat'] = float(re.sub(r'.*"lat"\s*:\s*([\d.]+)\s*[,}\n]+.*', r'\1', result))
                loc['location']['lng'] = float(re.sub(r'.*"lng"\s*:\s*([\d.]+)\s*[,}\n]+.*', r'\1', result))
                loc['accuracy'] = float(re.sub(r'.*"accuracy"\s*:\s*([\d.]+)\s*[,\}\n]+.*', r'\1', result))
                loc['status'] = re.sub(r'.*"status"\s*:\s*"(.*?)"\s*[,}\n]+.*', r'\1', result)
                return loc
            except:
                eyefi_logger.debug("Geolocation service response contains no coordinates: " + result)
                return None

    @staticmethod
    def write_xmp(name, latitude, longitude):
        if latitude > 0:
            ref_lat = "N"
        else:
            ref_lat = "S"
        latitude = str(abs(latitude)).split('.')
        latitude[1] = str(float('0.' + latitude[1]) * 60)
        latitude = ','.join(latitude) + ref_lat

        if longitude > 0:
            ref_lon = "E"
        else:
            ref_lon = "W"
        longitude = str(abs(longitude)).split('.')
        longitude[1] = str(float('0.' + longitude[1]) * 60)
        longitude = ','.join(longitude) + ref_lon

        xmp_file = open(name, "w")
        xmp_file.write(
            "<?xpacket begin='\xef\xbb\xbf' id='W5M0MpCehiHzreSzNTczkc9d'?>\n<x:xmpmeta xmlns:x='adobe:ns:meta/' "
            "x:xmptk='EyeFiServer'>\n<rdf:RDF "
            "xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>\n<rdf:Description rdf:about='' "
            "xmlns:exif='http://ns.adobe.com/exif/1.0/'>\n<exif:GPSLatitude>" + latitude +
            "</exif:GPSLatitude>\n<exif:GPSLongitude>" + longitude +
            "</exif:GPSLongitude>\n<exif:GPSVersionID>2.2.0.0</exif:GPSVersionID>\n</rdf:Description>\n</rdf:RDF>\n"
            "</x:xmpmeta>\n<?xpacket end='w'?>\n")
        xmp_file.close()

    def get_photo_status(self, post_data):
        post_data_str = post_data.decode('utf-8')
        handler = EyeFiContentHandler()
        xml.sax.parseString(post_data_str, handler)

        # Create the XML document to send back
        doc = xml.dom.minidom.Document()

        soap_element = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "SOAP-ENV:Envelope")
        soap_element.setAttribute("xmlns:SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/")
        soap_body_element = doc.createElement("SOAP-ENV:Body")

        get_photo_status_response_element = doc.createElement("GetPhotoStatusResponse")
        get_photo_status_response_element.setAttribute("xmlns", "http://localhost/api/soap/eyefilm")

        fileid_element = doc.createElement("fileid")
        fileid_element_text = doc.createTextNode("1")
        fileid_element.appendChild(fileid_element_text)

        offset_element = doc.createElement("offset")
        offset_element_text = doc.createTextNode("0")
        offset_element.appendChild(offset_element_text)

        get_photo_status_response_element.appendChild(fileid_element)
        get_photo_status_response_element.appendChild(offset_element)

        soap_body_element.appendChild(get_photo_status_response_element)

        soap_element.appendChild(soap_body_element)
        doc.appendChild(soap_element)

        return doc.toxml(encoding="UTF-8")

    def _get_mac_upload_key_dict(self):
        d = {self.server.config['mac']: self.server.config['upload_key']}
        return d

    def start_session(self, post_data):
        post_data_str = post_data.decode('utf-8')
        eyefi_logger.debug("Delegating the XML parsing of start_session post_data to EyeFiContentHandler()")
        handler = EyeFiContentHandler()
        parser = xml.sax.parseString(post_data_str, handler)

        eyefi_logger.debug("Extracted elements: " + str(handler.extracted_elements))

        # Retrieve it from C:\Documents and Settings\<User>\Application Data\Eye-Fi\Settings.xml
        mac_to_upload_key_map = self._get_mac_upload_key_dict()
        mac = handler.extracted_elements["macaddress"]
        upload_key = mac_to_upload_key_map[mac]
        eyefi_logger.debug("Got MAC address of " + mac)
        eyefi_logger.debug("Setting Eye-Fi upload key to " + upload_key)

        credential_string = mac + handler.extracted_elements["cnonce"] + upload_key
        eyefi_logger.debug("Concatenated credential string (pre MD5): " + credential_string)

        # Return the binary data represented by the hexadecimal string
        # resulting in something that looks like "\x00\x18V\x03\x04..."
        binary_credential_string = binascii.unhexlify(credential_string)

        # Now MD5 hash the binary string
        md5_hash = hashlib.md5()
        md5_hash.update(binary_credential_string)

        # Hex encode the hash to obtain the final credential string
        credential = md5_hash.hexdigest()

        # Create the XML document to send back
        doc = xml.dom.minidom.Document()

        soap_element = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "SOAP-ENV:Envelope")
        soap_element.setAttribute("xmlns:SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/")
        soap_body_element = doc.createElement("SOAP-ENV:Body")

        start_session_response_element = doc.createElement("StartSessionResponse")
        start_session_response_element.setAttribute("xmlns", "http://localhost/api/soap/eyefilm")

        credential_element = doc.createElement("credential")
        credential_element_text = doc.createTextNode(credential)
        credential_element.appendChild(credential_element_text)

        snonce_element = doc.createElement("snonce")
        snonce_element_text = doc.createTextNode("%x" % random.getrandbits(128))
        snonce_element.appendChild(snonce_element_text)

        transfer_mode_element = doc.createElement("transfermode")
        transfer_mode_element_text = doc.createTextNode(handler.extracted_elements["transfermode"])
        transfer_mode_element.appendChild(transfer_mode_element_text)

        transfer_mode_timestamp_element = doc.createElement("transfermodetimestamp")
        transfer_mode_timestamp_element_text = doc.createTextNode(handler.extracted_elements["transfermodetimestamp"])
        transfer_mode_timestamp_element.appendChild(transfer_mode_timestamp_element_text)

        upsync_allowed_element = doc.createElement("upsyncallowed")
        upsync_allowed_element_text = doc.createTextNode("true")
        upsync_allowed_element.appendChild(upsync_allowed_element_text)

        start_session_response_element.appendChild(credential_element)
        start_session_response_element.appendChild(snonce_element)
        start_session_response_element.appendChild(transfer_mode_element)
        start_session_response_element.appendChild(transfer_mode_timestamp_element)
        start_session_response_element.appendChild(upsync_allowed_element)

        soap_body_element.appendChild(start_session_response_element)

        soap_element.appendChild(soap_body_element)
        doc.appendChild(soap_element)

        return doc.toxml(encoding="UTF-8")


def run_eyefi():
    config = dict()
    config['mac'] = os.environ.get('CARD_MAC', '00:00:00:00:00:00').replace(':', '').replace('-', '')
    config['upload_key'] = os.environ.get('CARD_UPLOAD_KEY', '00000000000000000000000000000000')
    # TODO: Allow multiple mac/upload keys
    config['geotag_enable'] = os.environ.get('GEOTAG_ENABLE', '0')
    config['geotag_lag'] = os.environ.get('GEOTAG_LAG', '3600')
    config['geotag_accuracy'] = os.environ.get('GEOTAG_ACCURACY', '140000')
    config['upload_dir'] = os.environ.get('UPLOAD_DIR', 'uploads/')

    server_address = ('', 59278)

    # Create an instance of an HTTP server. Requests will be handled
    # by the class EyeFiRequestHandler
    eyefi_server = EyeFiServer(server_address, EyeFiRequestHandler)
    eyefi_server.config = config
    eyefi_logger.info("Eye-Fi server started listening on port " + str(server_address[1]))
    eyefi_server.serve_forever()


def main():
    run_eyefi()


if __name__ == "__main__":
    main()