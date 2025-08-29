Your OSCAL JSON files are the machine-readable "database" of your compliance posture; now you need to generate the "reports."

The standard way to do this is by using a transformation process. You take the structured OSCAL data and apply a stylesheet to render it into a human-readable format like HTML or PDF.

There are two primary methods for doing this:

Method 1: The Official NIST OSCAL Conversion Tools (Recommended)

NIST provides a set of command-line tools that are specifically designed to convert OSCAL JSON or XML files into beautifully formatted HTML documents. This is the most direct and standardized approach.

    What they are: A set of Java-based command-line utilities that use XSLT (eXtensible Stylesheet Language Transformations) and CSS to perform the conversion.

    How it works: You run a simple command, providing your OSCAL file as input, and the tool generates a self-contained HTML file as output.

Step-by-Step Example:

    Download the Tools: Get the latest oscal-cli.jar file from the NIST OSCAL GitHub repository releases page:

        https://github.com/usnistgov/oscal-cli/releases

    Run the Conversion Command: Open a terminal in the directory where you downloaded the CLI and your OSCAL files are located. Run the following command to convert your System Security Plan (SSP):
    Bash

    # Ensure you have a Java Runtime Environment (JRE) installed

    # Command to convert an SSP from JSON to HTML
    java -jar oscal-cli.jar -ssp ssp_comprehensive_template.json -o . --to html

    View the Output: The command will create a new directory (e.g., ssp-a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d) containing a ssp.html file. When you open this file in a web browser, you will see a fully formatted, easy-to-read version of your SSP, with a table of contents, linked controls, and clear sections.

You can use the same process for your other OSCAL files:

    Assessment Plan: java -jar oscal-cli.jar -sap ocp4_assessment_plan.json -o . --to html

    Assessment Results: java -jar oscal-cli.jar -sar ocp4_assessment_results.json -o . --to html

Method 2: Use a GRC / OSCAL-Aware Platform

This is the more integrated, production-pipeline approach. Instead of running manual conversions, you use a tool that has this functionality built-in.

    What it is: A commercial GRC platform or an open-source tool like FedRAMP's GovReady-Q that can natively ingest OSCAL files.

    How it works:

        Your automation pipeline pushes the OSCAL JSON files to the GRC tool's API.

        The tool automatically parses the files and displays the information in a web-based, interactive dashboard.

        It will have features to generate human-readable reports (often as PDFs) on demand, directly from the web interface.

This method is ideal for a production environment because it automates the reporting and provides a centralized place for stakeholders to view the current compliance posture without ever needing to see the underlying JSON.
