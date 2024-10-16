<h1>User Defined Functions in Python for Cosmian KMS</h1>

These functions let you perform large scale encryption and decryption operations to the Cosmian KMS.
Please see
the [KMS documentation](https://docs.cosmian.com/cosmian_key_management_system/encrypting_and_decrypting_at_scale/) for
more information.

The functions are exposed in the `cosmian_kms` module.

Please checks the tests in the `tests` directory for examples on how to use the functions and benchmarks. 

The functions expects pandas dataframes to perform encryption and decryption operations with
the following protocols :

- AES-GCM (NIST SP 800-38D)
- AES GCM SIV (RFC 8452)
- AES XTS (NIST SP 800-38E)
- ChCha20-Poly1305 (RFC 8439)

