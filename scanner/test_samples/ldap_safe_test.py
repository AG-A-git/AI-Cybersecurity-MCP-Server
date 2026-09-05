ldap_filter = "(uid=admin)"

connection.search(
    "dc=example,dc=com",
    ldap_filter
)