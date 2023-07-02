import os
import subprocess
import datetime
import requests
import unicodedata
import re
from urllib.parse import urlparse
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, PageBreak, Preformatted,
    Table, TableStyle)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus.doctemplate import PageTemplate, NextPageTemplate
from reportlab.platypus.flowables import DocExec
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.units import cm
from reportlab.platypus import Flowable
from reportlab.lib.colors import black
from reportlab.platypus import Paragraph
from reportlab.platypus.flowables import KeepTogether
from reportlab.platypus import Image
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate

# sudo apt-get install subfinder assetfinder getallurls parsero
# pip install snallygaster git-dumper

def remove_non_printable_chars(text):
    """
    Removes non-printable characters from a given text.
    """
    return ''.join(c for c in text if unicodedata.category(c)[0] != 'C' or c in ('\n', '\t'))

def footer_on_page(canvas, doc):
    p = Paragraph("admin@robotsecurity.com", style=ParagraphStyle('footer', alignment=1))  # Set alignment to center (1)
    width, height = p.wrap(doc.width, doc.bottomMargin)
    x = (doc.width - width) / 2  # Calculate the x-coordinate to center the footer
    p.drawOn(canvas, x, doc.bottomMargin - height)

def get_subdomains(outfile_list, original_domain):
    """
    Compiles unique subdomains from all the output files generated.
    Only includes subdomains that contain the original domain.
    """
    subdomains = set()
    for outfile in outfile_list:
        print(f"Checking file {outfile} for subdomains...")  # Debugging line
        try:
            with open(outfile, "r") as f:
                data = f.read().splitlines()
                #print(f"Data from {outfile}: {data}")  # Debugging line
                for line in data:
                    matches = re.findall(r'(http://|https://)?([\w.-]*\.' + re.escape(original_domain) + r'/?)', line)
                    #print(f"Matches found in {outfile}: {matches}")  # Debugging line
                    for match in matches:
                        normalized_match = match[1].lower().rstrip('/')  # Normalize the URL
                        subdomains.add(normalized_match)
        except FileNotFoundError:
            #print(f"File {outfile} not found.")
            continue
    return list(subdomains)

def run_command(command, outfile=None):
    """
    Executes a shell command and optionally writes its output to a file.
    If outfile is provided, dirsearch's own output file is used.
    If the command fails, it writes an error message to the output file and returns 2.
    If the command succeeds but produces no output, it returns 1.
    If the command succeeds and produces output, it returns 0.
    """
    try:
        if outfile is None:
            outfile = f"{command.split()[0]}_out.txt"
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            with open(outfile, "w") as out:
                out.write(result.stdout.decode())
        else:
            result = subprocess.run(command, stderr=subprocess.PIPE, shell=True)
            # Check if command was dirsearch and if so, modify the outfile to point to the actual output file
            if "dirsearch" in command:
                match = re.search(r"Output File: (.*\.txt)", result.stderr.decode())
                if match:
                    outfile = match.group(1)

        # Check if command was successful
        if result.returncode == 0:
            # Check if output was produced
            if outfile and os.path.exists(outfile) and os.stat(outfile).st_size > 0:
                return 0, outfile
            else:
                return 1, outfile
        else:
            # Handle common errors
            stderr = result.stderr.decode().lower()
            with open(outfile, "w") as out:
                if "command not found" in stderr:
                    out.write(f"{command.split()[0]} Command Not installed")
                elif "wpscan" in command and "the remote website is up, but does not seem to be running wordpress" in stderr:
                    out.write("Site does not seem to be running wordpress")
                else:
                    out.write(f"Command '{command}' failed with return code {result.returncode}")
            return 2, outfile

            with open(outfile, "w") as out:
                if "command not found" in stderr:
                    out.write(f"{command.split()[0]} Command Not installed")
                    return 3, outfile  # return code 3 indicates command not installed

    except Exception as e:
        print(f"Error occurred: {e}")
        return 2, outfile
        
def create_pdf(successful_commands, no_output_commands, failed_commands, not_installed_commands, pdf_filename, user_input, subdomains):
    """
    Generates a PDF report that includes the outputs of the successful commands, 
    the names of the commands that produced no output, and the names of the failed commands.
    """
    # Define PDF styles
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='CommandStyle', fontSize=12, textColor=colors.red))
    styles.add(ParagraphStyle(name='OutputStyle', fontSize=10, textColor=colors.black, fontName="Courier"))
    styles.add(ParagraphStyle(name='footer', fontSize=8, textColor=colors.grey))

    # Change pagesize parameter to your desired size (e.g., 20 inches by 11 inches)
    doc = BaseDocTemplate(pdf_filename, pagesize=(20*inch, 11*inch))

    # Define a frame for the main content
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id='normal')

    # Define a PageTemplate that uses the frame and the footer_on_page function
    page_template = PageTemplate(id='Page1', frames=frame, onPage=footer_on_page)

    # Add the PageTemplate to the document
    doc.addPageTemplates([page_template])

    # Adjust the margins as needed
    doc.rightMargin = 1*inch
    doc.leftMargin = 1*inch
    doc.topMargin = 1*inch
    doc.bottomMargin = 1*inch
    doc.allowSplitting = 0
    story = []

    # Add report header
    #This should be in the top left corner of the page
    story.append(Paragraph(f"Penetration Test Report: {user_input}", styles['Title']))

    # This should be in the top right corner
    story.append(Paragraph(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d')}", styles['Title']))
    story.append(Spacer(1, 0.2*inch))
    story.append(Spacer(1, 0.2*inch))

    # Download image
    image_url = 'https://i.ibb.co/MZsXm4J/websecl-image.png'
    image_path = 'websecl-image.png'
    response = requests.get(image_url)
    with open(image_path, 'wb') as file:
        file.write(response.content)

    # Add image to the story
    story.append(Image(image_path, 2*inch, 2*inch))  # Adjust size as needed
    story.append(Spacer(1, 0.2*inch))

    story.append(Spacer(1, 0.2*inch))
    # This should be in the middle of the page
    story.append(Paragraph(f"Prepared By: Robot Security", styles['Title']))

    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph(f"Subdomains identified: {len(subdomains)}", styles['Title']))
    
    for i, (command, filename) in enumerate(successful_commands):
        story.append(PageBreak())
        story.append(Paragraph(f'Command {i+1}: {command}', styles['CommandStyle']))
        story.append(Spacer(1, 0.2*inch))
        
        with open(filename, 'r') as file:
            lines = file.readlines()
            clean_output = remove_non_printable_chars(''.join(line for line in lines if "An exception has occurred" not in line))
        
            for line in clean_output.split('\n'):
                para = Paragraph(line, styles['OutputStyle'])
                story.append(para)

    # Add commands with no output
    if no_output_commands:
        story.append(PageBreak())
        story.append(Paragraph("Commands that produced no output but did not fail:", styles['Heading2']))
        story.append(Spacer(1, 0.2*inch))
        for command, filename in no_output_commands:
            story.append(Paragraph(f"Command: {command}", styles['CommandStyle']))
            story.append(Spacer(1, 0.2*inch))

    # Add failed commands
    if failed_commands:
        story.append(PageBreak())
        story.append(Paragraph("Attempted commands that failed:", styles['Heading2']))
        story.append(Spacer(1, 0.2*inch))
        for command, filename in failed_commands:
            story.append(Paragraph(f"Command: {command}", styles['CommandStyle']))
            story.append(Spacer(1, 0.2*inch))

    # Add not installed commands
    if not_installed_commands:
        story.append(PageBreak())
        story.append(Paragraph("Attempted commands that were not installed:", styles['Heading2']))
        story.append(Spacer(1, 0.2*inch))
        for command, filename in not_installed_commands:
            story.append(Paragraph(f"Command: {command}", styles['CommandStyle']))
            story.append(Spacer(1, 0.2*inch))

    # Build the PDF
    try:
        doc.multiBuild(story)
    finally:
        # Delete the image file
        if os.path.isfile(image_path):
            os.remove(image_path)

def run_dirsearch_on_subdomains(subdomains):
    """
    For each subdomain, runs the dirsearch command and outputs to a separate file.
    """
    successful_commands = []
    no_output_commands = []
    failed_commands = []

    for subdomain in subdomains:
        dirsearch_outfile = f"dirsearch_{subdomain}_out.txt"
        dirsearch_command = f"dirsearch --no-color -q -e php,js,conf,config,txt,py,sh,zip,rar -f --exclude-texts='Not found, 404, cloudflare, cloudfront, blocked' -u {subdomain} -o {dirsearch_outfile}"
        print(f"Running {dirsearch_command}")
        result, outfile = run_command(dirsearch_command, dirsearch_outfile)
        if result == 0:
            print(f"{dirsearch_command} was successful, output file: {outfile}")
            successful_commands.append((dirsearch_command, outfile))
        elif result == 1:
            print(f"{dirsearch_command} produced no output, output file: {outfile}")
            no_output_commands.append((dirsearch_command, outfile))
        else:
            print(f"{dirsearch_command} failed, output file: {outfile}")
            failed_commands.append((dirsearch_command, outfile))
    
    return successful_commands, no_output_commands, failed_commands

def main():
    """
    Main function to execute all steps of the penetration test.
    """
    user_input = input("Enter your domain: ")

    # Define all commands to be executed
    commands = [
        ("#dmitry -wines " + user_input, None),
        ("#theHarvester -b baidu,bevigil,bing,bingapi,certspotter,crtsh,dnsdumpster,duckduckgo,hackertarget,otx,threatminer,urlscan,yahoo -l 1000 -d " + user_input, None),
        ("#assetfinder --subs-only " + user_input, None),
        ("#subfinder -silent -t 10 -timeout 3 -nW -d " + user_input, None),
        ("#dig +noall +answer -t NS " + user_input, None),
        ("#dig +noall +answer -t MX " + user_input, None),
        ("#fierce --domain " + user_input, None),
        ("#dnsrecon -t std -d " + user_input, None),
        ("#snallygaster --nowww " + user_input, None),
        ("#whatweb -v " + user_input, None),
        ("#parsero -sb -u " + user_input, None),
        ("#wpscan --url " + user_input + " --random-user-agent --no-update", None),
        ("#testssl --openssl /usr/bin/openssl " + user_input, None),
        ("#mkdir chad_results; chad -sos no -d chad_results -tr 100 -q 'ext:txt OR ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx' -s *." + user_input, None),
        ("#git-dumper https://" + user_input + "/.git git_dumper_results", None),
        ("#getallurls -subs " + user_input, None),
        ("#dirsearch -e php,js,conf,config,txt,py,sh,zip,rar -f --exclude-texts='Not found, 404, cloudflare, cloudfront, blocked' -u " + user_input, None)
    ]

    successful_commands = []
    no_output_commands = []
    failed_commands = []
    not_installed_commands = []

    # Run commands and sort them into successful, no output and failed
    for command, outfile in commands:
        print(f"Running {command}")
        result, outfile = run_command(command, outfile)  # Get the actual output filename
        if result == 0:
            successful_commands.append((command, outfile))
        elif result == 1:
            no_output_commands.append((command, outfile))
        elif result == 3:
            not_installed_commands.append((command, outfile))
        else:
            failed_commands.append((command, outfile))
    
    
    # Extract subdomains from the output files
    subdomains = get_subdomains([outfile for command, outfile in commands if outfile is not None], user_input)
    
    # Run dirsearch on each subdomain and collect the results
    dirsearch_successful, dirsearch_no_output, dirsearch_failed = run_dirsearch_on_subdomains(subdomains)
    
    # Append dirsearch results to the command results
    successful_commands += dirsearch_successful
    no_output_commands += dirsearch_no_output
    failed_commands += dirsearch_failed
    
    # Collect all output files
    all_outfiles = [outfile for command, outfile in successful_commands + no_output_commands + failed_commands]
    
    # Extract subdomains from all the output files
    subdomains = get_subdomains(all_outfiles, user_input)
    
    # Create a PDF from the output files
    create_pdf(successful_commands, no_output_commands, failed_commands, not_installed_commands, "command_outputs.pdf", user_input, subdomains)
    
    # Delete all the output files
    for outfile in all_outfiles:
        try:
            os.remove(outfile)
        except FileNotFoundError:
            continue

if __name__ == "__main__":
    main()
