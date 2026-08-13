VULNERABILITY_MAPPING = {
    "SQL Injection": {
        "owasp": "A03:2021 Injection",
        "cwe": "CWE-89"
    },

    "XSS": {
        "owasp": "A03:2021 Injection",
        "cwe": "CWE-79"
    },

    "Cross Site Scripting": {
        "owasp": "A03:2021 Injection",
        "cwe": "CWE-79"
    },

    "Hardcoded Credentials": {
        "owasp": "A07:2021 Identification and Authentication Failures",
        "cwe": "CWE-798"
    },

    "Weak Cryptography": {
        "owasp": "A02:2021 Cryptographic Failures",
        "cwe": "CWE-327"
    }
}



def get_mapping(vulnerability):

    vulnerability = vulnerability.strip()

    if vulnerability in VULNERABILITY_MAPPING:

        return VULNERABILITY_MAPPING[vulnerability]


    return {

        "owasp": "Unknown",

        "cwe": "Unknown"

    }



if __name__ == "__main__":

    vulnerabilities = [

        "SQL Injection",

        "XSS",

        "Hardcoded Credentials"

    ]


    for vulnerability in vulnerabilities:

        result = get_mapping(vulnerability)

        print("\n", vulnerability)

        print(result)
print(get_mapping("Buffer Overflow"))