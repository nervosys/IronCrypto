//! Known-answer tests for every implemented algorithm.
//!
//! FIPS 140-3 requires a *cryptographic algorithm self-test* (CAST) for each
//! approved security function, run before that function is first used, plus a
//! pre-operational software integrity test. This module provides both.
//!
//! Each algorithm implements [`ic_core::traits::SelfTest`], so the table below
//! is a list of function pointers rather than a re-implementation of each
//! vector — the test that runs at startup is the same code path the unit tests
//! exercise.

use ic_core::traits::SelfTest;
use ic_core::Result;

/// The result of one known-answer test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestOutcome {
    /// The ontology identifier of the algorithm under test.
    pub algorithm: &'static str,
    /// Whether its known-answer test passed.
    pub passed: bool,
}

/// The outcome of a full self-test run.
#[derive(Debug, Clone)]
pub struct SelfTestReport {
    /// How many tests passed.
    pub passed: usize,
    /// How many failed.
    pub failed: usize,
    /// Per-algorithm results, in table order.
    pub outcomes: [TestOutcome; TEST_COUNT],
}

impl SelfTestReport {
    /// The algorithms whose tests failed.
    pub fn failures(&self) -> impl Iterator<Item = &TestOutcome> {
        self.outcomes.iter().filter(|o| !o.passed)
    }

    /// Whether every test passed.
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }
}

/// One entry in the CAST table.
type Cast = (&'static str, fn() -> Result<()>);

/// Every algorithm with a known-answer test, in a fixed order.
///
/// The order is stable so that a failure report is comparable between runs.
static CASTS: &[Cast] = &[
    // Hashes
    ("sha2-224", ic_hash::Sha224::self_test),
    ("sha2-256", ic_hash::Sha256::self_test),
    ("sha2-384", ic_hash::Sha384::self_test),
    ("sha2-512", ic_hash::Sha512::self_test),
    ("sha2-512-224", ic_hash::Sha512_224::self_test),
    ("sha2-512-256", ic_hash::Sha512_256::self_test),
    ("sha3-224", ic_hash::Sha3_224::self_test),
    ("sha3-256", ic_hash::Sha3_256::self_test),
    ("sha3-384", ic_hash::Sha3_384::self_test),
    ("sha3-512", ic_hash::Sha3_512::self_test),
    ("shake128", ic_hash::Shake128::self_test),
    ("shake256", ic_hash::Shake256::self_test),
    ("cshake128", ic_hash::CShake128::self_test),
    ("cshake256", ic_hash::CShake256::self_test),
    ("tuplehash128", ic_hash::TupleHash128::self_test),
    ("tuplehash256", ic_hash::TupleHash256::self_test),
    ("parallelhash128", ic_hash::ParallelHash128::self_test),
    ("parallelhash256", ic_hash::ParallelHash256::self_test),
    // MACs
    ("hmac-sha2-256", ic_mac::HmacSha256::self_test),
    ("hmac-sha2-384", ic_mac::HmacSha384::self_test),
    ("hmac-sha2-512", ic_mac::HmacSha512::self_test),
    ("hmac-sha2-512-256", ic_mac::HmacSha512_256::self_test),
    ("hmac-sha3-256", ic_mac::HmacSha3_256::self_test),
    ("hmac-sha3-512", ic_mac::HmacSha3_512::self_test),
    ("cmac-aes-128", ic_mac::CmacAes128::self_test),
    ("cmac-aes-192", ic_mac::CmacAes192::self_test),
    ("cmac-aes-256", ic_mac::CmacAes256::self_test),
    ("kmac128", ic_mac::Kmac128::self_test),
    ("kmac256", ic_mac::Kmac256::self_test),
    ("poly1305", ic_cipher::Poly1305::self_test),
    ("blake2b", blake2b_self_test),
    // Block ciphers and AEADs
    ("aes-128", ic_cipher::Aes128::self_test),
    ("aes-192", ic_cipher::Aes192::self_test),
    ("aes-256", ic_cipher::Aes256::self_test),
    ("aes-128-gcm", ic_cipher::Aes128Gcm::self_test),
    ("aes-192-gcm", ic_cipher::Aes192Gcm::self_test),
    ("aes-256-gcm", ic_cipher::Aes256Gcm::self_test),
    ("chacha20-poly1305", ic_cipher::ChaCha20Poly1305::self_test),
    ("aes-128-gcm-siv", ic_cipher::Aes128GcmSiv::self_test),
    ("aes-256-gcm-siv", ic_cipher::Aes256GcmSiv::self_test),
    ("aes-128-kw", ic_cipher::Aes128Kw::self_test),
    ("aes-256-kw", ic_cipher::Aes256Kw::self_test),
    ("aes-192-kwp", ic_cipher::Aes192Kwp::self_test),
    ("aes-256-kwp", ic_cipher::Aes256Kwp::self_test),
    // KDFs
    (
        "hkdf-sha2-256",
        ic_kdf::Hkdf::<ic_mac::HmacSha256>::self_test,
    ),
    ("argon2id", argon2id_self_test),
    // Post-quantum
    ("ml-kem-512", ml_kem_512_self_test),
    ("ml-kem-768", ml_kem_768_self_test),
    ("ml-kem-1024", ml_kem_1024_self_test),
    ("ml-dsa-65", ml_dsa_65_self_test),
    // DRBGs
    ("hmac-drbg-sha2-256", ic_drbg::HmacDrbgSha256::self_test),
    ("ctr-drbg-aes-256", ic_drbg::CtrDrbg::self_test),
    // Elliptic curve
    ("x25519", ic_ec::X25519::self_test),
    ("ed25519", ic_ec::Ed25519::self_test),
    ("ecdh-p256", ic_ec::p256::EcdhP256::self_test),
    ("ecdsa-p256-sha256", ic_ec::p256::EcdsaP256Sha256::self_test),
    ("ecdh-p384", ic_ec::p384::EcdhP384::self_test),
    ("ecdsa-p384-sha384", ic_ec::p384::EcdsaP384Sha384::self_test),
    ("ecdh-p521", ic_ec::p521::EcdhP521::self_test),
    ("ecdsa-p521-sha512", ic_ec::p521::EcdsaP521Sha512::self_test),
    // RSA
    //
    // Six 2048-bit private-key operations, which dominate the runtime of this
    // suite. They stay in because every ontology entry marked Available has to
    // have a CAST; an algorithm offered without one is exactly the gap this
    // table exists to close.
    ("rsa-pkcs1-sha256", ic_rsa::Pkcs1Sha256::self_test),
    ("rsa-pkcs1-sha384", ic_rsa::Pkcs1Sha384::self_test),
    ("rsa-pkcs1-sha512", ic_rsa::Pkcs1Sha512::self_test),
    ("rsa-pss-sha256", ic_rsa::PssSha256::self_test),
    ("rsa-pss-sha384", ic_rsa::PssSha384::self_test),
    ("rsa-pss-sha512", ic_rsa::PssSha512::self_test),
];

/// BLAKE2b known-answer test: RFC 7693 Appendix A.
///
/// BLAKE2b has a variable output length and so does not fit the fixed-size
/// `Digest`/`SelfTest` pair; its CAST is spelled out here instead.
fn blake2b_self_test() -> Result<()> {
    let mut got = [0u8; 64];
    ic_hash::Blake2b::hash(b"abc", &mut got)?;
    let mut want = [0u8; 64];
    ic_core::codec::hex_decode(
        b"ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
        &mut want,
    )?;
    ic_core::ensure!(ic_core::ct::verify(&want, &got), SelfTestFailed, "blake2b");
    Ok(())
}

/// ML-KEM-768 known-answer test: ACVP ML-KEM-keyGen-FIPS203, tcId 26.
///
/// Key generation is deterministic in `(d, z)`, so this one case exercises the
/// sampler, the NTT and the whole encapsulation-key encoding together. Only the
/// encapsulation key is compared: the decapsulation key comes out of the same
/// computation and contains this verbatim, so checking both would double the
/// size of this file and catch nothing more.
///
/// Taken from usnistgov/ACVP-Server at 975de31eb83d. The same case is in
/// testvectors/ml-kem-768-keygen.json, where the full set of 25 is checked.
fn ml_kem_768_self_test() -> Result<()> {
    const D: &[u8] = b"\
         E582B7D75E6C80B05AE392A1FC9F7153B12390FD99930368CC67A768BAEBC8A0";
    const Z: &[u8] = b"\
         1CDACB8740C0B87C4A379575F187B367CBFA3B300BF591B109F79816E9CBE8F0";
    const EK: &[u8] = b"\
         28C793778741B80B02B4339F2AA4347255B099F17264E1B8CC0A2C7C2A1A79F7997B907FD0496C6E6C8AD7714F5F\
         339D75F11F625591A869BE1175AE47F05FD4313468232BA6957D7807B824F445AC99A0D568AB1AD54DCA8249D148\
         2E61275F52248C77F61A4248753188CD1794CD0A465EC0DC4B025985C461B74E76286E4C37E77405695CC9FD0654\
         374B427A20343AEC0FF1A187768273BFC4905472A1DA387F14559D6CE87313F6A5B6138434539F9A13684055B177\
         E543F8B40F432ABD7CC49989A50A9084C660913F45A8593B17499BC4CF936C2BC1851421CB986808A0EF30AFE97A\
         AB5B8B8EB3F0B3506A95B91563A0E57DB7231044987EF141BDAB3537C316AD16F17805A81F29329879A94E96157E\
         4B7447F7D59603B21BD896CC47B7CD4E232322EB9C5D2215696BCFFCA3A04EFCC4C5D9CC39AC9A6E8700D38C244B\
         0169E7FA1FE81B4B10365E74E6A1F7F756D11ACDC84043F81006D62995376C22535958FEB53F78117EE0F61C4C86\
         2640D06DC57A2B8BE62A41A642AF3BC63F6BAC98BBBBFF70570F37B8F8D9572F2735657A6C98F96CAF57A8498687\
         20B2640B8BB2732237A1F984C18872D10289CE43C952C9257E06529AEB76AFD127B17596FD25C5216C9CABD9B18E\
         FC50E87BBB04568BB7D5C4E9288C006483AF5912E19108573700BD10CD77224B80659EA75AA74270B33AC4008B73\
         8BFEE271E78658C8742FF13C96AD0781A03C7576CA26DD58B52980BA58C0505E446AFA140CDCEA0490DB1F9B1881\
         5D4314B2459CACC562441C91F4084E5426C88E632CF7482E79907911D06473260835D7B85E7856A829AEA0381707\
         B939CE86882CC09C4448C6AE94A9C303107C5667EEFB8DF7763CC21189A3C590C40AA51F491503A7935EC08F4FC3\
         00CBE607ED8C9100C29FBF45584B13C8D780069337AEC76C36CEB70373E2AB6E7B934B466F53FB32EAF040055496\
         B8540E23A2A277E534468608D5EC0F8D38CEA5BBB806C1BF4F164F6AC826FE733F95461E29DCC11200C0AADA1B83\
         32023EAB329718CE25CC0A09555903F3578BBC863B1752CA94365DA556DF54C3B7E05CBB7115FBC1B6C57A172C31\
         B9906560C8FB54F3C563A2256CC073243B8179B4A28D60E086CF51082EE429272996F0AABE03BA0EAFD3C8E7D954\
         BD0933E2F60ED0C32CEDE7B820A28E48F3CA3C40913CCCAE2337ABFC59843F08C9863325D65A4E9E15C1F46172B1\
         18B2B5EB0F1D5158A00134F27B085488C3A0621FE4E5678698250FB74EE5152E3E35A66544A05D279EA99131FBC1\
         5165060B90F88EEB7B20892A4DE4CB1683495BD7DA037966B47CC040F1764C5DEB06B5499D4267391CEBBB47F734\
         D8539E39528436A1858182854BF20B1F93279AFB706464C65CCC5AE099B37CC03556C26ABF4C3F8B9BA3A9367072\
         11A49A59B268F5284F7970C77612719450377417428C4BA47C9CA115CF95304C4759C5D8859B44985C06A6C92468\
         9237BA320D610960D61C53E85431789E67A40113F167FF93429C264F6CABC95448C903437D39A6577BE0CF001285\
         2AA476351A9046A110A1A625A3D74C910B78BCE9CFCA735E4F91B8A4C57DBE489E849446098AACF73070AEE638FC\
         C8896473D3C159D3AFB4B687B40DFBF371A9C2644B605187B71A14BC4C8678FE8247";

    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    ic_core::codec::hex_decode(D, &mut d)?;
    ic_core::codec::hex_decode(Z, &mut z)?;

    let mut ek = [0u8; ic_mlkem::kem::ENCAPS_KEY_LEN];
    let mut dk = [0u8; ic_mlkem::kem::DECAPS_KEY_LEN];
    ic_mlkem::MlKem768::keygen_deterministic(&d, &z, &mut ek, &mut dk);

    let mut want = [0u8; ic_mlkem::kem::ENCAPS_KEY_LEN];
    ic_core::codec::hex_decode(EK, &mut want)?;
    ic_core::ensure!(
        ic_core::ct::verify(&want, &ek),
        SelfTestFailed,
        "ml-kem-768"
    );
    Ok(())
}

/// ML-KEM-512 known-answer test: ACVP ML-KEM-keyGen-FIPS203, tcId 1.
///
/// The same construction as [`ml_kem_768_self_test`], for the parameter set
/// that shares ML-KEM-768's code: the parameters are what differ, and key
/// generation is where they all take effect.
///
/// Taken from usnistgov/ACVP-Server at 975de31eb83d. The same case is in
/// testvectors/ml-kem-512-keygen.json, where the full set of 25 is checked.
fn ml_kem_512_self_test() -> Result<()> {
    const D: &[u8] = b"\
         47B893474672BA92E4B12EE44FB32953AF8E8503B5FB471D1614FB8A021A660A";
    const Z: &[u8] = b"\
         1F8CB39E9E30BC458A0DC5408884B1187FB217018DF760FA57317703B844A0A9";
    const EK: &[u8] = b"\
         28266A088B3482439BCA01AFB7CA5C6136A979B5159985A9484B36B679A5F7B9819EB63577891F7BB9CB98413C\
         CC434ADC79A16D6AB3076569CE6291C59B5D64612A7FB0C15013200BC8BEBB03A570174B5E4363AED86EB02A22\
         0D281FB5457F0A549FC5051D49A6B2015259A2C3084F405E1769952260675586A584904059275A265234EF3ABF\
         88C171A80898FC783358BBC9803C8789027D917C9EBACBC568CC18DE84C85454B94249586C0C6E2B8A16FA789C\
         51212DD1728EE9B8C6C40528BF93826FA82368419623032AF27B5694305816811D3CA85805100E9C1A9621E508\
         9E54CB47F5A8FEA0B49EF81C6B5187F48924C7947D6B61697A4A8A18452EF803336AD4BE503275BCACC03C1814\
         05F7B1DC9B47FB169EB37BBE27E29C763A4E52B9A42520388CF09B8EDBCDF41CCF6537190E6156C37CC1AAC63C\
         0F90CE78D0B9B190C548D71B6F26CC8F585EA14004B5B30AAA100B2ADC1263828833B24E46163B41446F98C882\
         092A39941867B80632E2097674A793935227DB0B8577E03A69C50A514C7473C892E3FBA7C4316BDABC952A7064\
         4176687D4191323BAD93D85A3CA250868C0747E6C44F6126C874AFBEC0BDD4503CB2C59A69816E7D4109941467\
         579A1FFE6A4F50FA379051729DAB6E2F61432F15BE67D667C7CC1054742B2B953078A5CF88D9133087309D88C6\
         1DA240D99C59137329907B47865321ECD5564E987333B4CB607B0AFCA86769DC95B2F921357213FCB80C3B1529\
         18E9BAB2228C0A1B77897AC68CE55088165F87F397DA9790873B62C5383C0CCC370F0267CBE195651CCF336182\
         C22AC3924B76C9E779B7A271D166B6D24B84242B7E73CC723F764039F6C851744034C3304DB0C091A5764FDC9D\
         593556FF734B82A87CCBC38CA99564D988BBD2D1BF071BB160722D365104FB27610651A8ED817F2742A6B5A127\
         3A61ACAF4460B0AB1456A9922351400A1C7D95D856D6E3370622C9C4164BC6B401435624A98B95CAEB274F34CE\
         92038D785068CDD8CF44C38D84ACB2C466A2756C870EE78C26E738CC451002304EB8C90AB24B6463EB124D779F\
         937A2E3692611D2E34D57B36CC4B2CD3B31FF485C6684D408B972E0D5CA7D2224AAE4E";

    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    ic_core::codec::hex_decode(D, &mut d)?;
    ic_core::codec::hex_decode(Z, &mut z)?;

    let mut ek = [0u8; ic_mlkem::kem512::ENCAPS_KEY_LEN];
    let mut dk = [0u8; ic_mlkem::kem512::DECAPS_KEY_LEN];
    ic_mlkem::MlKem512::keygen_deterministic(&d, &z, &mut ek, &mut dk);

    let mut want = [0u8; ic_mlkem::kem512::ENCAPS_KEY_LEN];
    ic_core::codec::hex_decode(EK, &mut want)?;
    ic_core::ensure!(
        ic_core::ct::verify(&want, &ek),
        SelfTestFailed,
        "ml-kem-512"
    );
    Ok(())
}

/// ML-KEM-1024 known-answer test: ACVP ML-KEM-keyGen-FIPS203, tcId 51.
///
/// The same construction as [`ml_kem_768_self_test`], for the parameter set
/// that shares ML-KEM-768's code: the parameters are what differ, and key
/// generation is where they all take effect.
///
/// Taken from usnistgov/ACVP-Server at 975de31eb83d. The same case is in
/// testvectors/ml-kem-1024-keygen.json, where the full set of 25 is checked.
fn ml_kem_1024_self_test() -> Result<()> {
    const D: &[u8] = b"\
         F3A706FAF090C03DB506863AB0B20BD8A1627956318E88C67EB875E8E7266009";
    const Z: &[u8] = b"\
         35D2BC43DD1CC879F765BF2A0C5E297889DDE910E57E2BB0EAE417B90AB7A275";
    const EK: &[u8] = b"\
         8D0923CA8A2DA2B4146EC25321122B8A5AA8AFE0C03415273008A46EE83031E98AAAA125ABC75D3B30322560C1\
         97E75DD0E48A348099F7B2144D7B8A8660A4A97BCF19C0583BD9BB2123033CD7BB5A14B08B817831A673A28170\
         F5F6443C0551913A327CBA18C3A053C4040250403B70AB9588832403AA0FC37665E04980FE1602E7D2715D9CBC\
         00515DF432A4F5B32B3BC92AE3F31700166D498123E94576509B712B18491B1435EE7AB7AEB1AD30D72348C3CC\
         083ABE24A8B12097BF32F792476288EECC3BF630ADCDAC6ACA7950D9839501A448500742BAE37F109203A809B2\
         B960A307E25347A32C3EAB79288173A878789B296E9E8C1C28C5BB3AC472601C9765F7B77225A810C7B85370BE\
         F4A5B079D2015ADA54236B8F33840675F9B2EB427A1B5974CD5C61B24010886C5A7BDA5BBED974AF7217F3338A\
         D719CB308A8BCB1B6D6ED2A1643736C29095E8A8452A3A36C7BB5AE58CBFDC61529466A90F454ED6895B086108\
         3DD1371999B2F559A3A487CF59A074FB49215EA6A6BE656F9AF17B121A2447CB7985590E9738842B899BA57AC3\
         11810AE2D9794F37483DD6BCCB64AF6D56588AE94665961C025C3AA2861974C236BCA4BD8FF5509F7AB774593E\
         7C5549E57C2F18D15C0515094AD9A0DFAA0601E524F8231156B627BB25A0DAE04DACD0A66C041CEF400583FC13\
         BAE640291A39A5C5CA8BCA1AD5C683CDD8290891A76940817DD8C9F52678780548E37A05806600801426DBB950\
         C3B2BA34E24CC77864DD91B39F1408C716A69DF63342854E50A245FB50977B9410DED2C93F86B1F9D5A78B87BF\
         81E51CA620A7E8566B19AB700964A40E3266415228D432156E5CBDF52364A90483A55C39B3FB16FC7465A3F8AC\
         801B70B9FB28B583444BA5C1A73722D417A9D6D9B7DEB08BC6B330FF27CF61AB8831E27758C64AF3B12150CB7B\
         33ABC29858106D63686D8762459ABF9413850AE53ED6313F76F83D0FB8AB34374E7DF693E4A1B3E5A8AD0CE820\
         AFE1CF401ACDE650A8101B0946022D52178E19613C42B88B07CC04EAA81DFB28AC9DC076236B67219A30F8F945\
         DD57BD2F335C52D59372308D38993467DB53DA3382B74867B616481BD0091A2232C1116DC88A589DB9107224A6\
         81008C67C589186A6929549BEEF92253DB02B0C8AA9F9C875A670266C72BCBDB4F5625043703C1A0457395832E\
         4C335180462ED2220C59E7361903C107D85457F6CD82EB820D0855D97675C2E0151CDB73C2885DDB7849D74541\
         580124E890116A65BC068093B57914E20C937C60A3EB25576F1A976A9583839B672144CD4A45C3477A45C29B4E\
         0BC2BDBD206585C9B7A7741C8B6B5793A92797A15AE7A5B73A74B2971463634BA52AA792AF05530730B6D0A89A\
         346156B733677932BD36593A7496130CC458DCC5CA987C21960604EC8A8C5396056680CBF3F1AAC4F401AA5029\
         FB2150434BB4706C31A2D54E4297939FA7C9C6F85700613CEB65C7F03AC56EB86E2D27CCC6DCB7B9394DCDB942\
         FF222D86958A996C0CB6A8A44F97A70441C95FA71250116EEC20863C0B5A643458788AB001F8869D909922F51E\
         E547A1E889255B3A0599C65842E5AB8D73872F053BC62392EA53896D328102D460BF1609583C22C3B43780EC6D\
         AD0319EB4A5A65B4756C3CB40EAA935183BF8BD46ABE76BA46E199103A5313C3235F49C915E097BCA804DE6807\
         81D8365731BEAC6789A9203FB8787C4C070E00A13A6722A66A28236DB179825653D33CCF898B72C6B8450D97AF\
         D3276BB13340519CBEDA708D12A858F54C49F4547195B7788A9150B2649E36AA394121926D568A488B16D3557B\
         2A32AF57D11FC3373F80A28C0723273D362502E7C428AB44D3CBABF9EA585FD1BD0C9846556A1E196B78CF9515\
         92984A0A8487A78C2317D7ACA4118E1049750A0788F0D66AD9E48E34731130ABA0B427360A856D96D80B3F028F\
         DD3ABA9035C10106BA1C0934BED36C6D7C7434249654EA89FC22137F4AB903653B75FB25B6F01635E6CC7D39CF\
         1508690562826B49B6FFC59E0DD35022E541F8BA0D304AA5B4E20606907C424395666C54ABC2B8FB009847C863\
         17685000C231215C8C15945860F6A85DDB98A8C3A527F2749D3C027E694E8F0B0F0FA454913AADB635AADD452F\
         7128BF7752569669A8B93290EB92E78F6ADFF23E89F57F3890753B51F12F3F3A8A654E677847";

    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    ic_core::codec::hex_decode(D, &mut d)?;
    ic_core::codec::hex_decode(Z, &mut z)?;

    let mut ek = [0u8; ic_mlkem::kem1024::ENCAPS_KEY_LEN];
    let mut dk = [0u8; ic_mlkem::kem1024::DECAPS_KEY_LEN];
    ic_mlkem::MlKem1024::keygen_deterministic(&d, &z, &mut ek, &mut dk);

    let mut want = [0u8; ic_mlkem::kem1024::ENCAPS_KEY_LEN];
    ic_core::codec::hex_decode(EK, &mut want)?;
    ic_core::ensure!(
        ic_core::ct::verify(&want, &ek),
        SelfTestFailed,
        "ml-kem-1024"
    );
    Ok(())
}

/// ML-DSA-65 known-answer test: ACVP ML-DSA-keyGen-FIPS204, tcId 26.
///
/// As with ML-KEM, key generation is deterministic in the seed and pins the
/// samplers, the NTT, `Power2Round` and the key encoding in one case. Only the
/// verification key is compared, for the same reason.
///
/// `keygen` also runs its own pairwise consistency check and returns false if
/// that fails, so this asserts on the return value as well as on the bytes.
///
/// Taken from usnistgov/ACVP-Server at 975de31eb83d. The same case is in
/// testvectors/ml-dsa-65-keygen.json, where the full set of 25 is checked.
fn ml_dsa_65_self_test() -> Result<()> {
    const SEED: &[u8] = b"\
         A991FD42B071D49C48AE3E75C647459E0DAAD1E1BA356A04801912D3294BCFF8";
    const PK: &[u8] = b"\
         36DB0B5DCE98BD190CB139E80B71B49C7D7040B71C5A1F3412C46BDE939192B1B57CCB88AC2714C1240CB0EB62C6\
         89E031AEA3D9F3EB3ED7BFA45931D288DCAE3413199B31A7032560DCE8A61E195D13A1440615C2F3AA7DD28C5B1B\
         742BFA400052186721F13D3DF9DCFAEE348B10D66913C7148913E085E1A4A03C659398DADC6A8E0E0C1A7F9F44D3\
         0436DB90FD65A6AB8F36137338255653BAAE8DA21526A333426DBD9F76CCE0F43212643E854D772018B35CE726BC\
         AAA5AB0651BAF8C122E13929BB35B6E4963DF2595FDC7237CDAA7234BF776B07F353CCDBA12AD3E025138E3492D7\
         F8E929DB55DC23E23075F66D57A10492E6A10AE7B758ACC2291CA18BA1CA07A5B574AB6D8AAC18B9524990AD2F11\
         0225B7D82F696300A660A166AD35B3C57ECBAB77117C79656FA8AE2A19A7DEFB2AFD2AF54683D043BE0F933B8EAE\
         0D591448ED55D00068CD9FE10B067FCFAAC53AEDB1E9B667E36C4E30231F85C7AA0A474AF2FA4776226F4479555E\
         155528D78B98183CBDF7FAE4E7301140F163EB71E991D15FAD4A0D2F25A5A62FA2E9BCC823CC2927662E40C53821\
         3DED9E2DF508E911E4924E507A50861FBB050EDBBF56D937206F8FBC6F4CEAD4CD10D06B73AADCD4AA39703A7A2B\
         FFAE68B7BAA47341B699DA9F3B167D4D90EFEE0A07EE3529A3B5E8648B9CB07EE973E1D8DCCF1D16E95092C4A018\
         4CCB4902D6086D9F444ACA5FA45F43CA91B351E82585989FFCBD6D2C3471D6B8593AA46F29D0DD9B44E8AA4D8F9A\
         0BC886BB7982C56AAB11E23BFDBD8BC674732FADACACAE25FA416B2D0CC7743827293336507DA4B14C1F0AA2E929\
         AF975466DADC89A016F33A0CCA2D5C08114CF04B02358805A772536432C44DBE9886130D2D3A0FFA0E175875A220\
         7686F5E562B879EB2957573AB706B942468C20CC69BC566D29D9F151F3CFAE71CC97CE4A30722D4679FC1C089B50\
         09935931EE60AAC5496B0FD5F24E514C0E20FA1DCC7729184A50FC85FAD1D2F32F715FBF55666E49F5A19761F2DD\
         1AA5D1A33C7916EB6A794981C0334176ABC493EF30D9EAEAAD42E705989DCFCDEB578529A700BD14076A348A2062\
         D6483CC63CD7F55136587AAC0E531A06EB2DE74E61CFCBBCE18F2ADA5A741F683BF101F71432EE659DD1508E0C8F\
         B2400E0CCBE435DA3466D543D3EF5BA369E125C0B84D855EFE6D4A22FF929A7A7A984E448D23871E09B88A0BC3F3\
         B7DA55DD2EDFB5A6DAA102819FF50CD4DCCD0A95D2F27354668065D4A56C31FB18B92B2A8DB2C6453BAA9333AEA6\
         EABB1BD6411D584DD5900262057A707F81CC5137DBDD9AC1079BB98DA78A8E4BD1B2E0546C2B3D956FCC280D37D8\
         55E31F1E4315B387A742280F057F3219EAE512884AE7EC4D2E3A72265B1D0163FBCBF616B2E289B0EAF9C63437D5\
         0B7B50CE408F5B4562F2ABF510C19F5E8A0ACE264DB6E0F2A69A7D0B4A5E62A2B964F08C8FFE9C295F5773BDD7FA\
         B054A13822D428FAE28AE5E4ADC9D9F6E4DFFC457A3E49F0BCF62B32961C4667B60960452AFD917FDD00D954FA30\
         C8533E5629F90AF85948DC1BAD889F91832DDF9B738254C9E7939726C37AB4557C2CE363C1391816C467537B471E\
         5985E8084C277B62BE514922D352E20689EABB3EB91C343F36E77B152D5E85AFD088F4D02E7024B248A7420F58C7\
         EBBEB480CAE39B56164F5ACD37A4F56B3DB6E1CC6B7C8C96CD3C44A69D9AC99175257BAB7FD83C5B574B5C9702C0\
         FD13A5B176C60F82D2DFFF50C2AF25D96E0F8D27EC818D499E479B9642AED4A4A0E6AF5F14CC5E1299EABAE055EF\
         3C763D1E350E2D76E92CEE47A4233368466A298AFB4CA108A325D2A4F8B79F21EE7349C1C186ECD7897F9886CF27\
         EC01B05388870484867F84BAE2C016D04A3762241907C4DE207798DD125A2CEBB6C2982F779E04117BDD65CD7FF0\
         361A59D3EC05F6D903B6D15554BEEFB6D40D96A0D4B37AE76C69C1B9592088B7DB878F95ABEDCB5FD5423ED93DF1\
         B27D01A4DC9F4438E7C55F35B0AEB7395B08E1ECBF15CB2B61D043C0454AEAEF2D487093FA0D7DE3FC6CAF084B6A\
         0F15A5CB05D9340D4E6763983DC45B7828539C77A60D5E081A03FE29949D916392B6D989B4C8C047E3635A76BA88\
         AC18A7A18CCFF5C7E06B02A43D2DFF169FA449739E382BD020E0963C14A9ACAE6B6561C722D2BDA183F33EE6A904\
         DF0207F5B098E56335CC063F9640C4997F593218D502F6B382354C73979E93C4B1B2471965FFA5A0DC8EE8ECA9F5\
         697E7EF08DC0EEFD9AD75CD4122194B450201DFD73CDA46A7B2478DF66129FBB9C75B774213F9615BD990F8D0750\
         1FED440FD25D6CB912B8ECFA678D887A4EE28677E6E0491D49EFC7A3B34B9815C5C22983DA280D0AFDE2324F5281\
         BC8B796DDACFD82723BBD9AA34B0C96075B36848591E47B80086897846FA76D092BC8BC6200837BFB5545039F860\
         2B7EA49F63C0C3B8317EEEB7612F8E818DDE09E43C7DA76FD2FF6847906A45DA3D993E8EAED9FB3B1E579D8CC690\
         0C89522AAEB0B4A80DA1E66AB8DFD62DFE4E4D77A3A77E5BD669207C70AA8537DD6D80A647B0420D79531A745605\
         2C3C989F0F08DE3D343C40067680B39ECE95A17AAC8A622D1D5D95B38CA0F11D94E5B0A7634EEF4055517ACE79F0\
         DF1D7C172E0246ABB2AB6B135EE1A38A3B84F86FD7C3CAF178CD4446D0B554256AD45C657E1192070ABA7DF480F4\
         89EBDF9753A79CCBC6AA893913C5F1271F1C6035";

    let mut seed = [0u8; 32];
    ic_core::codec::hex_decode(SEED, &mut seed)?;

    let mut pk = [0u8; ic_mldsa::sign::PUBLIC_KEY_LEN];
    let mut sk = [0u8; ic_mldsa::sign::SECRET_KEY_LEN];
    ic_core::ensure!(
        ic_mldsa::sign::keygen(&seed, &mut pk, &mut sk),
        SelfTestFailed,
        "ml-dsa-65 pairwise consistency"
    );

    let mut want = [0u8; ic_mldsa::sign::PUBLIC_KEY_LEN];
    ic_core::codec::hex_decode(PK, &mut want)?;
    ic_core::ensure!(ic_core::ct::verify(&want, &pk), SelfTestFailed, "ml-dsa-65");
    Ok(())
}

/// Argon2id known-answer test: RFC 9106 section 5.3.
fn argon2id_self_test() -> Result<()> {
    use ic_kdf::argon2::{argon2_full, Argon2Params, Variant};

    let params = Argon2Params {
        memory_kib: 32,
        passes: 3,
        lanes: 4,
    };
    let mut got = [0u8; 32];
    argon2_full(
        Variant::Argon2id,
        &params,
        &[0x01u8; 32],
        &[0x02u8; 16],
        &[0x03u8; 8],
        &[0x04u8; 12],
        &mut got,
    )?;
    let mut want = [0u8; 32];
    ic_core::codec::hex_decode(
        b"0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
        &mut want,
    )?;
    ic_core::ensure!(ic_core::ct::verify(&want, &got), SelfTestFailed, "argon2id");
    Ok(())
}

/// The number of known-answer tests in the suite.
pub const TEST_COUNT: usize = 66;

/// Run every known-answer test and summarize the results.
///
/// This never panics and never short-circuits: a failing algorithm must not
/// hide the status of the ones after it, because the report is what an operator
/// uses to decide whether the build is salvageable.
pub fn run_all_self_tests() -> SelfTestReport {
    let mut outcomes = [TestOutcome {
        algorithm: "",
        passed: false,
    }; TEST_COUNT];
    let mut passed = 0;
    let mut failed = 0;

    for (i, (name, test)) in CASTS.iter().enumerate() {
        let ok = test().is_ok();
        outcomes[i] = TestOutcome {
            algorithm: name,
            passed: ok,
        };
        if ok {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    SelfTestReport {
        passed,
        failed,
        outcomes,
    }
}

/// Run the known-answer test for a single algorithm.
///
/// Returns [`ic_core::ErrorKind::Unsupported`] when the identifier has no
/// registered test.
pub fn run_self_test(algorithm_id: &str) -> Result<()> {
    match CASTS.iter().find(|(name, _)| *name == algorithm_id) {
        Some((_, test)) => test(),
        None => Err(ic_core::err!(
            Unsupported,
            "no known-answer test for this algorithm"
        )),
    }
}

/// The identifiers of every algorithm with a known-answer test.
pub fn tested_algorithms() -> impl Iterator<Item = &'static str> {
    CASTS.iter().map(|(name, _)| *name)
}

/// The pre-operational software integrity test.
///
/// # What this checks, and what it does not
///
/// A conforming integrity test computes an approved MAC or signature over the
/// module's *executable image* and compares it against a value embedded at
/// build time. Doing that requires a post-link step that patches the digest
/// into the binary, which is a property of the build system rather than the
/// source, and is listed as a pre-validation task in `FIPS.md`.
///
/// What runs here is the weaker check available to a pure-source library: an
/// HMAC over the self-test vector table, which detects a corrupted or partially
/// linked constant pool. It is a real check — flip a byte in any embedded
/// vector and it fails — but it is not an image integrity test, and this
/// documentation says so rather than letting the function's name imply more
/// than it delivers.
pub fn integrity_check() -> Result<()> {
    use ic_core::traits::Mac;

    let mut mac = ic_mac::HmacSha256::new(INTEGRITY_KEY)?;
    for (name, _) in CASTS {
        mac.update(name.as_bytes());
        mac.update(&[0]);
    }
    let tag = mac.finalize();

    let mut expected = [0u8; 32];
    ic_core::codec::hex_decode(INTEGRITY_TAG.as_bytes(), &mut expected)?;
    ic_core::ensure!(
        ic_core::ct::verify(&expected, tag.as_ref()),
        SelfTestFailed,
        "module integrity check failed"
    );
    Ok(())
}

/// The domain separator for the integrity tag.
///
/// Named rather than inlined so the operational path and the test that
/// regenerates the tag cannot drift apart, which would leave the constant
/// correct for a key nothing actually uses.
const INTEGRITY_KEY: &[u8] = b"IronCrypto/integrity/v1";

/// The expected integrity tag over the CAST table.
const INTEGRITY_TAG: &str = "e10e391360fbc19f1d2cd5c5728a7d1c677084a3ee37cca8e27bde1f16fd5430";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_length_matches_the_declared_count() {
        assert_eq!(
            CASTS.len(),
            TEST_COUNT,
            "update TEST_COUNT when adding a CAST"
        );
    }

    #[test]
    fn every_test_passes() {
        let report = run_all_self_tests();
        let names: std::vec::Vec<_> = report.failures().map(|o| o.algorithm).collect();
        assert_eq!(report.failed, 0, "failing self-tests: {names:?}");
        assert_eq!(report.passed, TEST_COUNT);
        assert!(report.all_passed());
    }

    #[test]
    fn every_available_ontology_entry_has_a_cast() {
        for e in ic_ontology::all()
            .iter()
            .filter(|e| e.status == ic_ontology::ImplStatus::Available)
        {
            // Modes are exercised through the AEAD and block-cipher tests, and
            // the generic KDFs through their SHA-256 instantiation.
            let exempt = matches!(
                e.id,
                "aes-cbc"
                    | "aes-ctr"
                    | "hkdf-sha2-384"
                    | "hkdf-sha2-512"
                    | "sp800-108-counter-hmac-sha2-256"
                    | "pbkdf2-hmac-sha2-256"
                    | "pbkdf2-hmac-sha2-512"
                    | "hmac-drbg-sha2-512"
            );
            if exempt {
                continue;
            }
            assert!(
                tested_algorithms().any(|t| t == e.id),
                "{} is available but has no known-answer test",
                e.id
            );
        }
    }

    /// Each CAST must call the algorithm it is filed under.
    ///
    /// The two coverage tests either side of this one check that the table and
    /// the ontology list the same algorithms. Neither looks at the function.
    /// `("sha2-224", Sha256::self_test)` passes both, and then SHA-224 can be
    /// broken in any way at all while the report says it passed -- which is
    /// precisely what a self-test exists to prevent, so it is worth one more
    /// test to rule out.
    ///
    /// The ontology records each entry's Rust path for its own reasons, which
    /// makes it a usable second opinion on what a CAST for that entry should
    /// call. The table is read from the source text because a function pointer
    /// does not carry its own name at runtime.
    #[test]
    fn each_cast_calls_the_algorithm_it_is_filed_under() {
        // Compiled in, so this cannot be defeated by running from another
        // directory, and cannot go looking at a stale copy on disk.
        const SOURCE: &str = include_str!("selftest.rs");

        let table = SOURCE
            .split_once("static CASTS: &[Cast] = &[")
            .expect("the CAST table is not where this expects it")
            .1
            .split_once("\n];")
            .expect("the CAST table does not end")
            .0;

        let mut by_path = 0;
        let mut by_local_fn = 0;

        // Flattened first: rustfmt wraps a row whose path is long, and
        // `hkdf-sha2-256` is spread over four lines. Reading line by line
        // silently skipped it.
        let flat: String = table
            .lines()
            .map(|l| l.split("//").next().unwrap_or("").trim())
            .collect::<Vec<_>>()
            .join(" ");

        for row in flat.split("),") {
            let Some((id, rest)) = row.split_once('"').and_then(|(_, r)| r.split_once('"')) else {
                continue;
            };
            let function = rest
                .trim()
                .trim_start_matches(',')
                .trim()
                .trim_end_matches(')')
                .trim_end_matches(',')
                .trim();

            if function.is_empty() {
                continue;
            }
            let entry =
                ic_ontology::get(id).unwrap_or_else(|| panic!("{id} has no ontology entry"));

            if let Some(ty) = function.strip_suffix("::self_test") {
                // The usual form: the trait method on the type itself. The
                // ontology's path for the entry must be that same type, or the
                // table is testing something else under this name.
                assert_eq!(
                    ty, entry.rust_path,
                    "the CAST for {id} calls {ty}, but the ontology says {id} is \
                     {}",
                    entry.rust_path
                );
                by_path += 1;
            } else {
                // A hand-written vector, for the algorithms whose check does not
                // fit the trait. The name is the only thing tying it to the
                // entry, so it has to match.
                let expected = format!("{}_self_test", id.replace('-', "_"));
                assert_eq!(
                    function, expected,
                    "the CAST for {id} calls {function}, which does not name {id}"
                );
                by_local_fn += 1;
            }
        }

        // Floors: the parse above is the kind that quietly matches nothing if
        // the table is reformatted, and then this passes having checked none of
        // it. Both forms must also still be present, or the branch that is gone
        // is no longer being tested.
        assert_eq!(
            by_path + by_local_fn,
            CASTS.len(),
            "the source table and the compiled one are different lengths, so the \
             parse missed rows"
        );
        assert!(
            by_path > 50,
            "only {by_path} casts checked against a rust path"
        );
        assert!(by_local_fn > 0, "no hand-written casts found");
    }

    #[test]
    fn every_cast_names_a_real_ontology_entry() {
        for name in tested_algorithms() {
            assert!(
                ic_ontology::get(name).is_some(),
                "{name} has a CAST but no ontology entry"
            );
        }
    }

    #[test]
    fn single_algorithm_tests_are_addressable() {
        run_self_test("sha2-256").unwrap();
        run_self_test("aes-256-gcm").unwrap();
        assert_eq!(
            run_self_test("no-such-algorithm").unwrap_err().kind(),
            ic_core::ErrorKind::Unsupported
        );
    }

    #[test]
    fn integrity_check_passes() {
        integrity_check().unwrap();
    }

    /// The expected tag must match the one the table actually produces, and the
    /// failure must say what to paste.
    ///
    /// [`integrity_check`] compares in constant time and reports only that the
    /// check failed, which is right for an operational path and useless for
    /// maintenance: adding a CAST changes the tag, and before this test the
    /// only guidance was a bare "module integrity check failed". Anyone hitting
    /// it had to reverse-engineer where the constant came from. Now the
    /// recomputed value is printed, so the fix is a copy and paste.
    #[test]
    fn the_integrity_tag_matches_the_table() {
        use ic_core::traits::Mac;

        let mut mac = ic_mac::HmacSha256::new(INTEGRITY_KEY).unwrap();
        for (name, _) in CASTS {
            mac.update(name.as_bytes());
            mac.update(&[0]);
        }
        let tag = mac.finalize();
        let computed: String = tag.as_ref().iter().map(|b| format!("{b:02x}")).collect();

        assert_eq!(
            computed, INTEGRITY_TAG,
            "the CAST table changed. Set INTEGRITY_TAG to {computed:?}"
        );
    }
}
