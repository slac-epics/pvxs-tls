/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <CLI/CLI.hpp>

#include "authnstd.h"
#include "authregistry.h"
#include "configstd.h"
#include "openssl.h"
#include "p12filefactory.h"

namespace pvxs {
namespace certs {

/**
 * @brief Define the options for the authnstd tool
 *
 * This function defines the options for the authnstd tool.
 *
 * @param app the CLI::App object to add the options to
 * @param config the configuration to override with command line parameters
 * @param verbose the verbose flag to set the logger level
 * @param debug the debug flag to set the logger level
 * @param daemon_mode the daemon mode flag to set daemon mode
 * @param show_version the show version flag to show version and exit
 * @param help the help flag to show this help message and exit
 * @param add_config_uri the add config uri flag to add a config uri to the generated certificate
 * @param usage the certificate usage client, server, or ioc
 * @param name the name
 * @param organization the organization
 * @param organizational_unit the organizational unit
 * @param country the country
 * @param cert_validity_mins the requested certificate validity in minutes
 */
void defineOptions(CLI::App &app, ConfigStd &config, bool &verbose, bool &debug, bool &daemon_mode, bool &force, bool &show_version, bool &help, bool &add_config_uri,
                   std::string &usage, std::string &name, std::string &organization, std::string &organizational_unit, std::string &country, std::string &cert_validity_mins) {
    app.set_help_flag("", "");  // deactivate built-in help

    app.add_flag("-h,--help", help);
    app.add_flag("-v,--verbose", verbose, "Make more noise");
    app.add_flag("-d,--debug", debug, "Debug mode");
    app.add_flag("-V,--version", show_version, "Print version and exit.");
    app.add_flag("--force", force, "Force overwrite if certificate exists.");
    app.add_flag("-a,--trust-anchor", config.trust_anchor_only, "Download Trust Anchor into keychain file");
    app.add_flag("-s,--no-status", config.no_status, "Request that status checking not be required for this certificate. PVACMS may ignore this request if it is configured to require all certificates to have status checking");

    app.add_flag("-D,--daemon", daemon_mode, "Daemon mode");
    app.add_flag("--add-config-uri", add_config_uri, "Add a config uri to the generated certificate");
    app.add_option("--cert-pv-prefix", config.cert_pv_prefix, "Specifies the pv prefix to use to contact PVACMS.  Default `CERT`");
    app.add_option("-i,--issuer", config.issuer_id, "The issuer ID of the PVACMS service to contact.  If not specified (default) broadcast to any that are listening");

    app.add_option("-u,--cert-usage", usage, "Certificate usage.  `server`, `client`, `ioc`");

    app.add_option("-t,--time", cert_validity_mins, "Duration of the certificate in minutes.  Default 30 days");

    app.add_option("-n,--name", name, "Specify Certificate's name");
    app.add_option("-o,--organization", organization, "Specify the Certificate's Organisation");
    app.add_option("--ou", organizational_unit, "Specify the Certificate's Organizational Unit");
    app.add_option("-c,--country", country, "Specify the Certificate's Country");
}

/**
 * @brief Show the help message for the authnstd tool
 *
 * This function shows the help message for the authnstd tool.
 *
 * @param program_name the program name
 */
void showHelp(const char *program_name) {
    std::cout << "authnstd - Secure PVAccess Standard Authenticator\n"
              << std::endl
              << "Generates client, server, or ioc certificates based on the Standard Authenticator. \n"
              << "Uses specified parameters to create certificates that require administrator APPROVAL before becoming VALID.\n"
              << std::endl
              << "usage:\n"
              << "  " << program_name << " [options]                          Create certificate in PENDING_APPROVAL state\n"
              << "  " << program_name << " (-h | --help)                      Show this help message and exit\n"
              << "  " << program_name << " (-V | --version)                   Print version and exit\n"
              << std::endl
              << "options:\n"
              << "  (-u | --cert-usage) <usage>                Specify the certificate usage.  client|server|ioc.  Default `client`\n"
              << "  (-n | --name) <name>                       Specify common name of the certificate. Default <logged-in-username>\n"
              << "  (-o | --organization) <organization>       Specify organisation name for the certificate. Default <hostname>\n"
              << "        --ou <org-unit>                      Specify organisational unit for the certificate. Default <blank>\n"
              << "  (-c | --country) <country>                 Specify country for the certificate. Default locale setting if detectable otherwise `US`\n"
              << "  (-t | --time) <minutes>                    Duration of the certificate in minutes.  e.g. 30 or 1d or 1y3M2d4m\n"
              << "  (-D | --daemon)                            Start a daemon that re-requests a certificate on expiration`\n"
              << "        --cert-pv-prefix <cert_pv_prefix>    Specifies the pv prefix to use to contact PVACMS.  Default `CERT`\n"
              << "        --add-config-uri                     Add a config uri to the generated certificate\n"
              << "        --force                              Force overwrite if certificate exists\n"
              << "  (-a | --trust-anchor)                      Download Trust Anchor into keychain file.  Do not create a certificate\n"
              << "  (-s | --no-status)                         Request that status checking not be required for this certificate\n"
              << "  (-i | --issuer) <issuer_id>                The issuer ID of the PVACMS service to contact.  If not specified (default) broadcast to any that are listening\n"
              << "  (-v | --verbose)                           Verbose mode\n"
              << "  (-d | --debug)                             Debug mode\n"
              << std::endl;
}

/*
 * @brief Read the command line parameters
 *
 * @param argc the number of command line arguments
 * @param argv the command line arguments
 * @param config the configuration to override with command line parameters
 * @param verbose the verbose flag to set the logger level
 * @param debug the debug flag to set the logger level
 * @param cert_usage the certificate usage client, server, or ioc
 * @return exit status 0 if successful, non-zero if an error occurs and we should exit
 */
int readParameters(int argc, char *argv[], ConfigStd &config, bool &verbose, bool &debug, uint16_t &cert_usage, bool &daemon_mode, bool &force) {
    auto program_name = argv[0];
    bool show_version{false}, help{false}, add_config_uri{false};
    std::string usage{"client"}, name, organization, organizational_unit, country, cert_validity_mins;

    CLI::App app{"authnstd - Secure PVAccess Standard Authenticator"};

    defineOptions(app, config, verbose, debug, daemon_mode, force, show_version, help, add_config_uri, usage, name, organization, organizational_unit, country, cert_validity_mins);

    CLI11_PARSE(app, argc, argv);

    // The built-in help from CLI11 is pretty lame, so we'll do our own
    // Make sure we update this help text when options change
    if (help) {
        showHelp(program_name);
        exit(0);
    }

    // Show the version and exit
    if (show_version) {
        if (argc > 2) {
            std::cerr << "Error: -V option cannot be used with any other options.\n";
            return 10;
        }
        std::cout << version_information;
        exit(0);
    }

    // Set the certificate usage based on the command line parameters
    if (usage == "server") {
        cert_usage = ssl::kForServer;
        if (config.tls_srv_keychain_file.empty()) {
            std::cerr << "You must set EPICS_PVAS_TLS_KEYCHAIN environment variable to create server certificates" << std::endl;
            return 10;
        }
    } else if (usage == "client") {
        cert_usage = ssl::kForClient;
        if (config.tls_keychain_file.empty()) {
            std::cerr << "You must set EPICS_PVA_TLS_KEYCHAIN environment variable to create client certificates" << std::endl;
            return 11;
        }
    } else if (usage == "ioc") {
        cert_usage = ssl::kForClientAndServer;
        if (config.tls_srv_keychain_file.empty()) {
            std::cerr << "You must set EPICS_PVAS_TLS_KEYCHAIN environment variable to create ioc certificates" << std::endl;
            return 12;
        }
    } else {
        std::cerr << "Usage must be one of `client`, `server`, or `ioc`: " << usage << std::endl;
        return 13;
    }

    // Pull out command line args to override config values
    if ( !name.empty()) {
        switch (cert_usage) {
            case ssl::kForClient: config.name = name; break;
            case ssl::kForServer: config.server_name = name; break;
            default: config.name = config.server_name = name; break;
        }
    }
    if ( !organization.empty()) {
        switch (cert_usage) {
            case ssl::kForClient: config.organization = organization; break;
            case ssl::kForServer: config.server_organization = organization; break;
            default: config.organization = config.server_organization = organization; break;
        }
    }
    if ( !organizational_unit.empty()) {
        switch (cert_usage) {
            case ssl::kForClient: config.organizational_unit = organizational_unit; break;
            case ssl::kForServer: config.server_organizational_unit = organizational_unit; break;
            default: config.organizational_unit = config.server_organizational_unit = organizational_unit; break;
        }
    }
    if ( !country.empty()) {
        switch (cert_usage) {
            case ssl::kForClient: config.country = country; break;
            case ssl::kForServer: config.server_country = country; break;
            default: config.country = config.server_country = country; break;
        }
    }
    if (!cert_validity_mins.empty()) {
        config.cert_validity_mins = CertDate::parseDurationMins(cert_validity_mins);
    }

    if ( config.trust_anchor_only) {
        const std::string tls_keychain_file = IS_FOR_A_SERVER_(cert_usage) ? config.tls_srv_keychain_file : config.tls_keychain_file;
        const std::string tls_keychain_pwd = IS_FOR_A_SERVER_(cert_usage) ? config.tls_srv_keychain_pwd : config.tls_keychain_pwd;

        // Create a keychain file from a trust anchor
        AuthNStd authenticator{};
        auto credentials = authenticator.getCredentials(config, !IS_FOR_A_SERVER_(cert_usage));
        auto cert_creation_request = authenticator.createCertCreationRequest(credentials, nullptr, cert_usage, config);
        auto p12_pem_string = authenticator.processCertificateCreationRequest(cert_creation_request, config.cert_pv_prefix, config.issuer_id, config.request_timeout_specified);

        // If the certificate was created successfully, write it to the keychain file
        if (!p12_pem_string.empty()) {
            // Attempt to write the certificate and private key to a cert file protected by the configured password
            auto file_factory = IdFileFactory::create(tls_keychain_file, tls_keychain_pwd, nullptr, nullptr, nullptr, p12_pem_string);
            file_factory->writeIdentityFile();
            std::cout << "Trust Anchor retrieved"<< std::endl;
            return -1;
        }
        std::cerr << "Failed to retrieve Trust Anchor" << std::endl;
        return 14;
    }

    return 0;
}

}  // namespace certs
}  // namespace pvxs

using namespace pvxs::certs;

/**
 * @brief Main function for the authnstd tool
 *
 * @param argc the number of command line arguments
 * @param argv the command line arguments
 * @return the exit status
 */
int main(const int argc, char *argv[]) { return runAuthenticator<ConfigStd, AuthNStd>(argc, argv); }
