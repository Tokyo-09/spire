/*
#[cfg(target_os = "windows")]
    use windows::{
        core::{w, PCWSTR},
        Win32::{
            Foundation::{HANDLE, HWND, WIN32_ERROR},
            Security::{
                Cryptography::{
                    CertCloseStore, CertGetCertificateChain, CertOpenSystemStoreW,
                    CMSG_SIGNER_INFO, CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA,
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                    CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE,
                    CryptQueryObject,
                },
                WinTrust::{
                    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA,
                    WINTRUST_DATA_0, WINTRUST_DATA_UICHOICE,
                    WINTRUST_FILE_INFO, WINTRUST_DATA_UICHOICE,
                    WINTRUST_DATA_REVOCATION_CHECKS, WINTRUST_DATA_UNION_CHOICE,
                },
            },
            System::SystemServices::CERT_CHAIN_CONFIG,
        },
};

pub fn verify_file_signature(file_path: &str) -> anyhow::Result<()> {
        // Convert path to PCWSTR
        let wide: Vec<u16> = file_path.encode_utf16().chain(std::iter::once(0)).collect();
        let file_path_ptr = PCWSTR(wide.as_ptr());

        // WINTRUST_FILE_INFO
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: file_path_ptr,
            hFile: HANDLE::default(),
            pgKnownSubject: ptr::null_mut(),
        };

        // WINTRUST_DATA (union field must be mutable)
        let mut trust_data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: ptr::null_mut(),
            pSIPClientData: ptr::null_mut::null_mut(),
            dwUIChoice: WINTRUST_DATA_UICHOICE(2), // WTD_UI_NONE
            fdwRevocationChecks: WINTRUST_DATA_REVOCATION_CHECKS(0),
            dwUnionChoice: WINTRUST_DATA_UNION_CHOICE(1), // WTD_CHOICE_FILE
            Anonymous: WINTRUST_DATA_0 {
                pFile: &mut file_info as *mut _,
            },
            dwStateAction: WINTRUST_DATA_STATE_ACTION(0),
            hWVTStateData: HANDLE::default(),
            pwszURLReference: PCWSTR::null(),
            dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(0),
            dwUIContext: WINTRUST_DATA_UICONTEXT(0),
            pSignatureSettings: ptr::null_mut(),
        };

        // Call WinVerifyTrust
        let mut guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let hr = unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut guid as *mut _,
                &mut trust_data as *mut _ as *mut std::ffi::c_void,
            )
        };

        match hr {
            0 => println!("Signature is valid and trusted! (0)"),
            0x800B0100 => return Err(anyhow!("No signature found")),
            _ => return Err(anyhow!("Verification failed: 0x{:X}", hr)),
        }
    }

    pub fn get_certificate_details(file_path: &str) -> Result<()> {
        // Path → PCWSTR
        let wide: Vec<u16> = file_path.encode_utf16().chain(std::iter::once(0)).collect();
        let file_path_ptr = PCWSTR(wide.as_ptr());

        // Query the file for a PKCS#7 signature
        let mut signer_info: *mut CMSG_SIGNER_INFO = ptr::null_mut();
        let ok = unsafe {
            CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                file_path_ptr.0 as *const _,
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                None,
                None,
                None,
                None,
                None,
                Some(&mut signer_info as *mut _ as *mut _),
                            )
                        };

                        if !ok {
                            let err = WIN32_ERROR::from_win32();
                            return Err(anyhow!("CryptQueryObject failed: {:?}", err));
                        }

                        // Open the “ROOT” system store (no provider handle needed)
                        let store = unsafe { CertOpenSystemStoreW(None, w!("ROOT")?)? };

                        // Build a CERT_CHAIN_PARA – the `CERT_CHAIN_CONFIG` you tried to use is
                        // actually a field inside this structure.
                        let chain_para = CERT_CHAIN_PARA {
                            cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as u32,
                            // default values are fine for a simple check
                            ..Default::default()
                        };

                        // Prepare the output pointer
                        let mut chain_ctx: *mut CERT_CHAIN_CONTEXT = ptr::null_mut();

                        // Build the chain
                        let ok = unsafe {
                            CertGetCertificateChain(
                                None,                     // default chain engine
                                signer_info as *const _,  // the certificate we got from CryptQueryObject
                                None,                     // use current system time
                                store,                    // the store we opened above
                                &chain_para,              // parameters
                                0,                        // dwFlags
                                None,                     // *pvReserved
                                ,
                                &mut chain_ctx,
                            )
                        };

                        if !ok {
                            let err = WIN32_ERROR::from_win32();
                            unsafe { CertCloseStore(Some(store), 0) };
                            return Err(anyhow!("CertGetCertificateChain failed: {:?}", err));
                        }

                        // -----------------------------------------------------------------
                        // At this point `chain_ctx` points to a valid CERT_CHAIN_CONTEXT.
                        // You can walk the chain and read fields such as issuer, subject,
                        // not‑before/after dates, etc.  Below is a tiny example that prints
                        // the subject name of the leaf certificate.
                        // -----------------------------------------------------------------
                        unsafe {
                            let chain = &*chain_ctx;
                            if chain.cElement > 0 {
                                let element = &*chain.rgpElement[0];
                                let cert = &*element.pCertContext;
                                // `CertGetNameStringW` is the usual way to obtain a readable name.
                                use windows::Win32::Security::Cryptography::{
                                    CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                };
                                let mut name_buf = [0u16; 256];
                                let len = CertGetNameStringW(
                                    cert,
                                    CERT_NAME_SIMPLE,
                                    0,
                                    None,
                                    &mut name_buf,
                                );
                                if len > 0 {
                                    let name = String::from_utf16_lossy(&name_buf[..(len as usize - 1)]);
                                    println!("Leaf certificate subject: {}", name);
                                }
                            }
                        }

                        // Clean up
                        unsafe {
                            CertCloseStore(Some(store), 0);
                            // The chain context must be freed with CertFreeCertificateChain
                            windows::Win32::Security::Cryptography::CertFreeCertificateChain(chain_ctx);
                        }

                        Ok(())
                    }
*/
