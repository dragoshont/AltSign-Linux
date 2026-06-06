//  Heavily based on sample code provided by Kabir Oberai (https://github.com/kabiroberai)

#include "AppleAPI.hpp"

#include "AnisetteData.h"

// libgsa — corecrypto-free GrandSlam crypto (OpenSSL-backed).
// Replaces the entire <corecrypto/*> dependency; see github.com/dragoshont/libgsa.
#include <gsa/srp.h>
#include <gsa/crypto.h>

#include <ostream>

using namespace std;
using namespace utility;                    // Common utilities like string conversions
using namespace web;                        // Common features like URIs.
using namespace web::http;                  // Common HTTP functionality
using namespace web::http::client;          // HTTP client features
using namespace concurrency::streams;       // Asynchronous streams

extern std::string make_uuid();

extern bool decompress(const uint8_t* input, size_t input_size, std::vector<uint8_t>& output);

#include "altsign_common.h"

std::vector<unsigned char> DataFromBytes(const char* bytes, size_t count)
{
	std::vector<unsigned char> data;
	data.reserve(count);
	for (int i = 0; i < count; i++)
	{
		data.push_back(bytes[i]);
	}

	return data;
}

/*
 * The "negotiation proof" running digest. corecrypto streamed this via
 * ccdigest_update into a ccdigest_ctx; libgsa exposes a one-shot SHA-256, so we
 * accumulate the same byte sequence in a buffer and hash it once at the end.
 * The first (di_info) argument is unused, kept only so the many call sites stay
 * byte-identical to the corecrypto version.
 */
void ALTDigestUpdateString(const void* /*unused*/, std::vector<unsigned char>* negProof, std::string string)
{
	negProof->insert(negProof->end(), string.begin(), string.end());
}

void ALTDigestUpdateData(const void* /*unused*/, std::vector<unsigned char>* negProof, std::vector<unsigned char>& data)
{
	uint32_t data_len = (uint32_t)data.size(); // 4 bytes for length, native byte order (matches ccdigest_update)
	const unsigned char* lenp = (const unsigned char*)&data_len;
	negProof->insert(negProof->end(), lenp, lenp + sizeof(data_len));
	negProof->insert(negProof->end(), data.begin(), data.end());
}

std::optional<std::vector<unsigned char>> ALTPBKDF2SRP(const void* /*unused*/, bool isS2k, std::string password, std::vector<unsigned char>& salt, int iterations)
{
	// s2k:    key = PBKDF2(SHA256(password),        salt, iters, 32)
	// s2k_fo: key = PBKDF2(hex(SHA256(password)),   salt, iters, 32)
	uint8_t outputBytes[GSA_SHA256_LEN];
	if (gsa_srp_s2k(password.c_str(), salt.data(), salt.size(), (uint32_t)iterations, isS2k ? 0 : 1, outputBytes) != 0)
	{
		return std::nullopt;
	}
	auto data = DataFromBytes((const char*)outputBytes, sizeof(outputBytes));
	return std::make_optional(data);
}

std::vector<unsigned char> ALTCreateSessionKey(gsa_srp_ctx* srp_ctx, const char* key_name)
{
	uint8_t session_key[GSA_SHA256_LEN];
	size_t key_len = sizeof(session_key);
	if (gsa_srp_session_key(srp_ctx, session_key, &key_len) != 0)
	{
		return std::vector<unsigned char>();
	}

	uint8_t hmac_bytes[GSA_SHA256_LEN];
	gsa_hmac_sha256(session_key, key_len, (const uint8_t*)key_name, strlen(key_name), hmac_bytes);

	return DataFromBytes((const char*)hmac_bytes, sizeof(hmac_bytes));
}

std::optional<std::vector<unsigned char>> ALTDecryptDataCBC(gsa_srp_ctx* srp_ctx, std::vector<unsigned char>& spd)
{
	auto extraDataKey = ALTCreateSessionKey(srp_ctx, "extra data key:");
	auto extraDataIV = ALTCreateSessionKey(srp_ctx, "extra data iv:");
	if (extraDataKey.size() < 32 || extraDataIV.size() < 16)
	{
		return std::nullopt;
	}

	uint8_t iv[16];
	memcpy(iv, extraDataIV.data(), sizeof(iv));

	std::vector<unsigned char> decryptedBytes(spd.size());
	size_t length = decryptedBytes.size();
	if (gsa_aes256_cbc_pkcs7_decrypt(extraDataKey.data(), iv, spd.data(), spd.size(), decryptedBytes.data(), &length) != 0)
	{
		return std::nullopt;
	}

	decryptedBytes.resize(length);
	return std::make_optional(decryptedBytes);
}

std::optional<std::vector<unsigned char>> ALTDecryptDataGCM(std::vector<unsigned char>& sk, std::vector<unsigned char>& encryptedData)
{
	// Layout: [3B "XYZ" version/AAD][16B IV][ciphertext][16B tag]
	if (encryptedData.size() < 35)
	{
		odslog("ERROR: Encrypted token too short.");
		return std::nullopt;
	}

	if (gsa_consttime_eq(encryptedData.data(), (const uint8_t*)"XYZ", 3) != 1)
	{
		odslog("ERROR: Encrypted token wrong version!");
		return std::nullopt;
	}

	size_t decrypted_len = encryptedData.size() - 35;
	std::vector<unsigned char> decryptedBytes(decrypted_len ? decrypted_len : 1);

	const uint8_t* aad = encryptedData.data();              // 3 bytes "XYZ"
	const uint8_t* iv  = encryptedData.data() + 3;          // 16 bytes
	const uint8_t* ct  = encryptedData.data() + 3 + 16;     // ciphertext
	const uint8_t* tag = encryptedData.data() + encryptedData.size() - 16;

	if (gsa_aes256_gcm_decrypt(sk.data(), iv, 16, aad, 3, ct, decrypted_len, tag, decryptedBytes.data()) != 0)
	{
		odslog("ERROR: Invalid tag version.");
		return std::nullopt;
	}

	decryptedBytes.resize(decrypted_len);
	return std::make_optional(decryptedBytes);
}

std::vector<unsigned char> ALTCreateAppTokensChecksum(std::vector<unsigned char>& sk, std::string adsid, std::vector<std::string> apps)
{
	// HMAC-SHA256(sk, "apptokens" || adsid || app-id-0 || app-id-1 || ...)
	std::vector<unsigned char> message;
	const char* key = "apptokens";
	message.insert(message.end(), key, key + strlen(key));
	message.insert(message.end(), adsid.begin(), adsid.end());
	for (auto& app : apps)
	{
		message.insert(message.end(), app.begin(), app.end());
	}

	uint8_t checksumBytes[GSA_SHA256_LEN];
	gsa_hmac_sha256(sk.data(), sk.size(), message.data(), message.size(), checksumBytes);

	return DataFromBytes((const char*)checksumBytes, sizeof(checksumBytes));
}

pplx::task<std::pair<std::shared_ptr<Account>, std::shared_ptr<AppleAPISession>>> AppleAPI::Authenticate(
	std::string appleID,
	std::string password,
	std::shared_ptr<AnisetteData> anisetteData,
	std::optional<std::function <pplx::task<std::optional<std::string>>(void)>> verificationHandler)
{
	auto adsidValue = std::make_shared<std::string>("");
	auto sessionValue = std::make_shared<AppleAPISession>();

	time_t time;
	struct tm* tm;
	char dateString[64];

	time = anisetteData->date().tv_sec;
	tm = localtime(&time);

	strftime(dateString, sizeof dateString, "%FT%T%z", tm);

	std::map<std::string, plist_t> clientDictionary = {
		{ "bootstrap", plist_new_bool(true) },
		{ "icscrec", plist_new_bool(true) },
		{ "loc", plist_new_string(anisetteData->locale().c_str()) },
		{ "pbe", plist_new_bool(false) },
		{ "prkgen", plist_new_bool(true) },
		{ "svct", plist_new_string("iCloud") },
		{ "X-Apple-I-Client-Time", plist_new_string(dateString) },
		{ "X-Apple-Locale", plist_new_string(anisetteData->locale().c_str()) },
		{ "X-Apple-I-TimeZone", plist_new_string(anisetteData->timeZone().c_str()) },
		{ "X-Apple-I-MD", plist_new_string(anisetteData->oneTimePassword().c_str()) },
		{ "X-Apple-I-MD-LU", plist_new_string(anisetteData->localUserID().c_str()) },
		{ "X-Apple-I-MD-M", plist_new_string(anisetteData->machineID().c_str()) },
		{ "X-Apple-I-MD-RINFO", plist_new_uint(anisetteData->routingInfo()) },
		{ "X-Mme-Device-Id", plist_new_string(anisetteData->deviceUniqueIdentifier().c_str()) },
		{ "X-Apple-I-SRL-NO", plist_new_string(anisetteData->deviceSerialNumber().c_str()) }
	};

	/* Begin libgsa (corecrypto-free) Logic */

	// Negotiation-proof running digest buffer. Heap-allocated and intentionally
	// leaked so it survives across the async .then() continuations that capture
	// it by value (matching the original malloc'd ccdigest_ctx lifetime).
	const void* di_info = nullptr;
	std::vector<unsigned char>* di_ctx = new std::vector<unsigned char>();

	// gsa_srp implements the Apple GrandSlam SRP-6a variant (RFC 5054 2048-bit
	// group, SHA-256, noUsernameInX) internally — there are no flags to flip.
	gsa_srp_ctx* srp_ctx = gsa_srp_new();
	if (srp_ctx == nullptr)
	{
		throw APIError(APIErrorCode::AuthenticationHandshakeFailed);
	}

	std::vector<std::string> ps = { "s2k", "s2k_fo" };
	ALTDigestUpdateString(di_info, di_ctx, ps[0]);
	ALTDigestUpdateString(di_info, di_ctx, ",");
	ALTDigestUpdateString(di_info, di_ctx, ps[1]);

	size_t A_size = 0;
	gsa_srp_start(srp_ctx, NULL, &A_size);
	char* A_bytes = (char*)malloc(A_size);
	size_t A_outlen = A_size;
	gsa_srp_start(srp_ctx, (uint8_t*)A_bytes, &A_outlen);

	auto A_data = DataFromBytes(A_bytes, A_size);

	ALTDigestUpdateString(di_info, di_ctx, "|");

	auto psPlist = plist_new_array();
	for (auto value : ps)
	{
		plist_array_append_item(psPlist, plist_new_string(value.c_str()));
	}	

	auto cpd = plist_new_dict();
	for (auto pair : clientDictionary)
	{
		plist_dict_set_item(cpd, pair.first.c_str(), pair.second);
	}

	std::map<std::string, plist_t> parameters = {
		{ "A2k", plist_new_data((const char *)A_bytes, A_size) },
		{ "ps", psPlist },
		{ "cpd", cpd },
		{ "u", plist_new_string(appleID.c_str()) },
		{ "o", plist_new_string("init") }
	};

	auto task = this->SendAuthenticationRequest(parameters, anisetteData)
		.then([=](plist_t plist) {

		size_t M_size = GSA_SHA256_LEN; // M1 is a SHA-256 digest (32 bytes)
		char* M_bytes = (char*)malloc(M_size);

		auto spNode = plist_dict_get_item(plist, "sp");
		if (spNode == nullptr)
		{
			throw APIError(APIErrorCode::InvalidResponse);
		}

		char* sp = nullptr;
		plist_get_string_val(spNode, &sp);

		bool isS2K = (std::string(sp) == "s2k");

		ALTDigestUpdateString(di_info, di_ctx, "|");

		if (sp)
		{
			ALTDigestUpdateString(di_info, di_ctx, sp);
		}

		auto cNode = plist_dict_get_item(plist, "c");
		auto saltNode = plist_dict_get_item(plist, "s");
		auto iterationsNode = plist_dict_get_item(plist, "i");
		auto bNode = plist_dict_get_item(plist, "B");

		if (cNode == nullptr || saltNode == nullptr || iterationsNode == nullptr || bNode == nullptr)
		{
			throw APIError(APIErrorCode::InvalidResponse);
		}

		char* c = nullptr;
		plist_get_string_val(cNode, &c);

		char* saltBytes = nullptr;
		uint64_t saltSize = 0;
		plist_get_data_val(saltNode, &saltBytes, &saltSize);

		uint64_t iterations = 0;
		plist_get_uint_val(iterationsNode, &iterations);

		char* B_bytes = nullptr;
		uint64_t B_size = 0;
		plist_get_data_val(bNode, &B_bytes, &B_size);

		auto salt = DataFromBytes((const char*)saltBytes, saltSize);
		auto B_data = DataFromBytes((const char*)B_bytes, B_size);

		auto passwordKey = ALTPBKDF2SRP(di_info, isS2K, password, salt, iterations);
		if (passwordKey == ::nullopt)
		{
			throw APIError(APIErrorCode::AuthenticationHandshakeFailed);
		}

		int result = gsa_srp_process(srp_ctx, appleID.c_str(),
			passwordKey->data(), passwordKey->size(),
			salt.data(), salt.size(),
			B_data.data(), B_data.size(), (uint8_t*)M_bytes);
		if (result != 0)
		{
			throw APIError(APIErrorCode::AuthenticationHandshakeFailed);
		}

		time_t time;
		struct tm* tm;
		char dateString[64];

		time = anisetteData->date().tv_sec;
		tm = localtime(&time);

		strftime(dateString, sizeof dateString, "%FT%T%z", tm);

		std::map<std::string, plist_t> clientDictionary = {
		{ "bootstrap", plist_new_bool(true) },
		{ "icscrec", plist_new_bool(true) },
		{ "loc", plist_new_string(anisetteData->locale().c_str()) },
		{ "pbe", plist_new_bool(false) },
		{ "prkgen", plist_new_bool(true) },
		{ "svct", plist_new_string("iCloud") },
		{ "X-Apple-I-Client-Time", plist_new_string(dateString) },
		{ "X-Apple-Locale", plist_new_string(anisetteData->locale().c_str()) },
		{ "X-Apple-I-TimeZone", plist_new_string(anisetteData->timeZone().c_str()) },
		{ "X-Apple-I-MD", plist_new_string(anisetteData->oneTimePassword().c_str()) },
		{ "X-Apple-I-MD-LU", plist_new_string(anisetteData->localUserID().c_str()) },
		{ "X-Apple-I-MD-M", plist_new_string(anisetteData->machineID().c_str()) },
		{ "X-Apple-I-MD-RINFO", plist_new_uint(anisetteData->routingInfo()) },
		{ "X-Mme-Device-Id", plist_new_string(anisetteData->deviceUniqueIdentifier().c_str()) },
		{ "X-Apple-I-SRL-NO", plist_new_string(anisetteData->deviceSerialNumber().c_str()) }
		};

		auto cpd = plist_new_dict();
		for (auto pair : clientDictionary)
		{
			plist_dict_set_item(cpd, pair.first.c_str(), pair.second);
		}

		std::map<std::string, plist_t> parameters = {
			{ "c", plist_new_string(c) },
			{ "M1", plist_new_data((const char*)M_bytes, M_size) },
			{ "cpd", cpd },
			{ "u", plist_new_string(appleID.c_str()) },
			{ "o", plist_new_string("complete") }
		};

		return this->SendAuthenticationRequest(parameters, anisetteData);
			}).then([=](plist_t plist) {

				auto M2_node = plist_dict_get_item(plist, "M2");
				if (M2_node == nullptr)
				{
					odslog("ERROR: M2 data not found!");
					throw APIError(APIErrorCode::InvalidResponse);
				}

				char* M2_bytes = nullptr;
				uint64_t M2_size = 0;
				plist_get_data_val(M2_node, &M2_bytes, &M2_size);

				if (gsa_srp_verify(srp_ctx, (const uint8_t*)M2_bytes) != 0)
				{
					odslog("ERROR: Failed to verify session.");
					throw APIError(APIErrorCode::AuthenticationHandshakeFailed);
				}

				ALTDigestUpdateString(di_info, di_ctx, "|");

				std::vector<unsigned char> spd;
				auto spdNode = plist_dict_get_item(plist, "spd");
				if (spdNode != nullptr)
				{
					char* spdBytes = nullptr;
					uint64_t spdSize = 0;
					plist_get_data_val(spdNode, &spdBytes, &spdSize);

					spd = DataFromBytes(spdBytes, spdSize);
					ALTDigestUpdateData(di_info, di_ctx, spd);
				}

				ALTDigestUpdateString(di_info, di_ctx, "|");

				auto scNode = plist_dict_get_item(plist, "sc");
				if (scNode != nullptr)
				{
					char* scBytes = nullptr;
					uint64_t scSize = 0;
					plist_get_data_val(scNode, &scBytes, &scSize);

					auto sc = DataFromBytes(scBytes, scSize);
					ALTDigestUpdateData(di_info, di_ctx, sc);
				}

				ALTDigestUpdateString(di_info, di_ctx, "|");

				auto npNode = plist_dict_get_item(plist, "np");
				if (npNode == nullptr)
				{
					odslog("ERROR: Missing np dictionary.");
					throw APIError(APIErrorCode::InvalidResponse);
				}

				char* npBytes = nullptr;
				uint64_t npSize = 0;
				plist_get_data_val(npNode, &npBytes, &npSize);

				auto np = DataFromBytes(npBytes, npSize);
				ALTDigestUpdateData(di_info, di_ctx, np);

				size_t digest_len = GSA_SHA256_LEN;
				if (np.size() != digest_len)
				{
					odslog("ERROR: Neg proto hash is too short.");
					throw APIError(APIErrorCode::AuthenticationHandshakeFailed);
				}

				unsigned char* digest = (unsigned char*)malloc(digest_len);
				gsa_sha256(di_ctx->data(), di_ctx->size(), digest);

				auto hmacKey = ALTCreateSessionKey(srp_ctx, "HMAC key:");
				unsigned char* hmac_out = (unsigned char*)malloc(digest_len);
				gsa_hmac_sha256(hmacKey.data(), hmacKey.size(), digest, digest_len, hmac_out);

				odslog("HMAC_OUT:");
				for (int i = 0; i < digest_len; i++)
				{
					char str[8];
					char byte = ((char*)hmac_out)[i];
					sprintf(str, "%d", byte);

					odslog("Byte:" << str);
				}

				odslog("NP:");
				for (int i = 0; i < digest_len; i++)
				{
					char str[8];
					char byte = ((char*)npBytes)[i];
					sprintf(str, "%d", byte);

					odslog("Byte:" << str);
				}

				/* Negotiation-proof HMAC check (kept disabled, as upstream):
				if (gsa_consttime_eq(hmac_out, np.data(), digest_len) != 1)
				{
					odslog("ERROR: Invalid neg prot hmac.");
					throw APIError(APIErrorCode::AuthenticationHandshakeFailed);
				}*/

				auto decryptedData = ALTDecryptDataCBC(srp_ctx, spd);
				if (decryptedData == ::nullopt)
				{
					odslog("ERROR: Could not decrypt login response.");
					throw APIError(APIErrorCode::AuthenticationHandshakeFailed);
				}

				odslog("Data: " << decryptedData->data());

				plist_t decryptedPlist = nullptr;
				plist_from_xml((const char *)decryptedData->data(), (int)decryptedData->size(), &decryptedPlist);

				if (decryptedPlist == nullptr)
				{
					odslog("ERROR: Could not parse decrypted login response plist!");
					throw APIError(APIErrorCode::InvalidResponse);
				}

				auto adsidNode = plist_dict_get_item(decryptedPlist, "adsid");
				auto idmsTokenNode = plist_dict_get_item(decryptedPlist, "GsIdmsToken");

				if (adsidNode == nullptr || idmsTokenNode == nullptr)
				{
					odslog("ERROR: adsid and /or idmsToken is nil.");
					throw APIError(APIErrorCode::InvalidResponse);
				}

				char* adsid = nullptr;
				plist_get_string_val(adsidNode, &adsid);

				char* idmsToken = nullptr;
				plist_get_string_val(idmsTokenNode, &idmsToken);

				auto statusDictionary = plist_dict_get_item(plist, "Status");
				if (statusDictionary == nullptr)
				{
					throw APIError(APIErrorCode::InvalidResponse);
				}

				bool isTwoFactorEnabled = false;

				auto authTypeNode = plist_dict_get_item(statusDictionary, "au");
				if (authTypeNode != nullptr)
				{
					char* authType = nullptr;
					plist_get_string_val(authTypeNode, &authType);

					if (std::string(authType) == "trustedDeviceSecondaryAuth")
					{
						isTwoFactorEnabled = true;
					}
				}

				if (isTwoFactorEnabled)
				{
					odslog("Requires two factor...");

					if (verificationHandler.has_value())
					{
						return this->RequestTwoFactorCode(adsid, idmsToken, anisetteData, *verificationHandler)
						.then([=](bool success) {
							return this->Authenticate(appleID, password, anisetteData, std::nullopt);
						});
					}
					else
					{
						throw APIError(APIErrorCode::RequiresTwoFactorAuthentication);
					}					
				}
				else
				{
					auto skNode = plist_dict_get_item(decryptedPlist, "sk");
					auto cNode = plist_dict_get_item(decryptedPlist, "c");

					if (skNode == nullptr || cNode == nullptr)
					{
						odslog("ERROR: No ak and /or c data.");
						throw APIError(APIErrorCode::InvalidResponse);
					}

					char* skBytes = nullptr;
					uint64_t skSize = 0;
					plist_get_data_val(skNode, &skBytes, &skSize);

					char* cBytes = nullptr;
					uint64_t cSize = 0;
					plist_get_data_val(cNode, &cBytes, &cSize);

					auto sk = DataFromBytes((const char*)skBytes, skSize);

					auto appsNode = plist_new_array();
					plist_array_append_item(appsNode, plist_new_string("com.apple.gs.xcode.auth"));

					auto checksum = ALTCreateAppTokensChecksum(sk, adsid, { "com.apple.gs.xcode.auth" });

					time_t time;
					struct tm* tm;
					char dateString[64];

					time = anisetteData->date().tv_sec;
					tm = localtime(&time);

					strftime(dateString, sizeof dateString, "%FT%T%z", tm);

					std::map<std::string, plist_t> clientDictionary = {
					{ "bootstrap", plist_new_bool(true) },
					{ "icscrec", plist_new_bool(true) },
					{ "loc", plist_new_string(anisetteData->locale().c_str()) },
					{ "pbe", plist_new_bool(false) },
					{ "prkgen", plist_new_bool(true) },
					{ "svct", plist_new_string("iCloud") },
					{ "X-Apple-I-Client-Time", plist_new_string(dateString) },
					{ "X-Apple-Locale", plist_new_string(anisetteData->locale().c_str()) },
					{ "X-Apple-I-TimeZone", plist_new_string(anisetteData->timeZone().c_str()) },
					{ "X-Apple-I-MD", plist_new_string(anisetteData->oneTimePassword().c_str()) },
					{ "X-Apple-I-MD-LU", plist_new_string(anisetteData->localUserID().c_str()) },
					{ "X-Apple-I-MD-M", plist_new_string(anisetteData->machineID().c_str()) },
					{ "X-Apple-I-MD-RINFO", plist_new_uint(anisetteData->routingInfo()) },
					{ "X-Mme-Device-Id", plist_new_string(anisetteData->deviceUniqueIdentifier().c_str()) },
					{ "X-Apple-I-SRL-NO", plist_new_string(anisetteData->deviceSerialNumber().c_str()) }
					};

					auto cpd = plist_new_dict();
					for (auto pair : clientDictionary)
					{
						plist_dict_set_item(cpd, pair.first.c_str(), pair.second);
					}

					std::map<std::string, plist_t> parameters = {
						{ "u", plist_new_string(adsid) },
						{ "app", appsNode },
						{ "c", plist_new_data((const char *)cBytes, cSize) },
						{ "t", plist_new_string(idmsToken) },
						{ "checksum", plist_new_data((const char*)checksum.data(), checksum.size()) },
						{ "cpd", cpd },
						{ "o", plist_new_string("apptokens") }
					};

					*adsidValue = std::string(adsid);
					return this->FetchAuthToken(parameters, sk, anisetteData)
					.then([=](std::string token) {
						auto session = std::make_shared<AppleAPISession>(*adsidValue, token, anisetteData);
						*sessionValue = *session;

						return this->FetchAccount(session);
					})
					.then([=](std::shared_ptr<Account> account) -> std::pair<std::shared_ptr<Account>, std::shared_ptr<AppleAPISession>> {
						return std::make_pair(account, sessionValue);
					});
				}
			});

	return task;
}

pplx::task<std::string> AppleAPI::FetchAuthToken(std::map<std::string, plist_t> requestParameters, std::vector<unsigned char> sk, std::shared_ptr<AnisetteData> anisetteData)
{
	auto apps = requestParameters["app"];
	auto appNode = plist_array_get_item(apps, 0);

	char* appName = nullptr;
	plist_get_string_val(appNode, &appName);

	std::string app(appName);

	return this->SendAuthenticationRequest(requestParameters, anisetteData)
	.then([=](plist_t plist) {

		auto encryptedTokenNode = plist_dict_get_item(plist, "et");
		if (encryptedTokenNode == nullptr)
		{
			throw APIError(APIErrorCode::InvalidResponse);
		}

		char* encryptedTokenBytes = nullptr;
		uint64_t encryptedTokenSize = 0;
		plist_get_data_val(encryptedTokenNode, &encryptedTokenBytes, &encryptedTokenSize);

		auto sk_copy = sk;

		auto encryptedToken = DataFromBytes(encryptedTokenBytes, encryptedTokenSize);
		auto decryptedToken = ALTDecryptDataGCM(sk_copy, encryptedToken);

		if (decryptedToken == ::nullopt)
		{
			odslog("ERROR: Failed to decrypt apptoken.");
			throw APIError(APIErrorCode::InvalidResponse);
		}

		plist_t decryptedTokenPlist = nullptr;
		plist_from_xml((const char *)decryptedToken->data(), decryptedToken->size(), &decryptedTokenPlist);

		if (decryptedTokenPlist == nullptr)
		{
			odslog("ERROR: Could not parse decrypted apptoken plist.");
			throw APIError(APIErrorCode::InvalidResponse);
		}

		auto tokensNode = plist_dict_get_item(decryptedTokenPlist, "t");
		if (tokensNode == nullptr)
		{
			throw APIError(APIErrorCode::InvalidResponse);
		}

		auto tokenDictionary = plist_dict_get_item(tokensNode, app.c_str());
		if (tokenDictionary == nullptr)
		{
			throw APIError(APIErrorCode::InvalidResponse);
		}

		auto tokenNode = plist_dict_get_item(tokenDictionary, "token");
		if (tokenNode == nullptr)
		{
			throw APIError(APIErrorCode::InvalidResponse);
		}

		char* token = nullptr;
		plist_get_string_val(tokenNode, &token);

		odslog("Got token for " << app << "!\nValue : " << token);

		return std::string(token);
	});
}

pplx::task<bool> AppleAPI::RequestTwoFactorCode(
	std::string dsid,
	std::string idmsToken,
	std::shared_ptr<AnisetteData> anisetteData,
	const std::function <pplx::task<std::optional<std::string>>(void)>& verificationHandler)
{
	std::string url = "/auth/verify/trusteddevice";
	auto encodedURI = web::uri::encode_uri(url);
	uri_builder builder(encodedURI);

	http_request request(methods::GET);
	request.set_request_uri(builder.to_string());

	time_t time;
	struct tm* tm;
	char dateString[64];

	time = anisetteData->date().tv_sec;
	tm = localtime(&time);

	strftime(dateString, sizeof dateString, "%FT%T%z", tm);

	std::string identityToken = dsid + ":" + idmsToken;

	std::vector<unsigned char> identityTokenData(identityToken.begin(), identityToken.end());
	auto encodedIdentityToken = utility::conversions::to_base64(identityTokenData);

	std::map<utility::string_t, utility::string_t> headers = {
		{"Content-Type", "text/x-xml-plist"},
		{"User-Agent", "Xcode"},
		{"Accept", "text/x-xml-plist"},
		{"Accept-Language", "en-us"},
		{"X-Apple-App-Info", "com.apple.gs.xcode.auth"},
		{"X-Xcode-Version", "11.2 (11B41)"},

		{"X-Apple-Identity-Token", encodedIdentityToken},
		{"X-Apple-I-MD-M", (anisetteData->machineID()) },
		{"X-Apple-I-MD", (anisetteData->oneTimePassword()) },
		{"X-Apple-I-MD-LU", (anisetteData->localUserID()) },
		{"X-Apple-I-MD-RINFO", (std::to_string(anisetteData->routingInfo())) },

		{"X-Mme-Device-Id", (anisetteData->deviceUniqueIdentifier()) },
		{"X-Mme-Client-Info", (anisetteData->deviceDescription()) },
		{"X-Apple-I-Client-Time", (dateString) },
		{"X-Apple-Locale", (anisetteData->locale()) },
		{"X-Apple-I-TimeZone", (anisetteData->timeZone()) },
	};

	for (auto& pair : headers)
	{
		if (request.headers().has(pair.first))
		{
			request.headers().remove(pair.first);
		}

		request.headers().add(pair.first, pair.second);
	}

	auto task = this->gsaClient().request(request)
		.then([=](http_response response)
			{
				return response.content_ready();
			})
		.then([=](http_response response)
			{
				odslog("Received 2FA response status code: " << response.status_code());
				return response.extract_vector();
			})
				.then([=](std::vector<unsigned char> decompressedData)
					{
						return verificationHandler();
					})
				.then([this, headers](std::optional<std::string> verificationCode) {
						if (!verificationCode.has_value())
						{
							throw APIError(APIErrorCode::RequiresTwoFactorAuthentication);
						}

						// Send verification code request.
						std::string url = "/grandslam/GsService2/validate";
						auto encodedURI = web::uri::encode_uri(url);
						uri_builder builder(encodedURI);

						http_request request(methods::GET);
						request.set_request_uri(builder.to_string());

						for (auto& pair : headers)
						{
							if (request.headers().has(pair.first))
							{
								request.headers().remove(pair.first);
							}

							request.headers().add(pair.first, pair.second);
						}

						request.headers().add("security-code", (*verificationCode));

						return this->gsaClient().request(request);
					})
				.then([=](http_response response)
					{
						return response.content_ready();
					})
				.then([=](http_response response)
					{
						odslog("Received 2FA response status code: " << response.status_code());
						return response.extract_vector();
					})
				.then([=](std::vector<unsigned char> compressedData)
					{
						std::vector<uint8_t> decompressedData;

						if (compressedData.size() > 2 && compressedData[0] == '<' && compressedData[1] == '?')
						{
							// Already decompressed
							decompressedData = compressedData;
						}
						else
						{
							decompress((const uint8_t*)compressedData.data(), (size_t)compressedData.size(), decompressedData);
						}

						std::string decompressedXML = std::string(decompressedData.begin(), decompressedData.end());

						plist_t plist = nullptr;
						plist_from_xml(decompressedXML.c_str(), (int)decompressedXML.size(), &plist);

						if (plist == nullptr)
						{
							throw APIError(APIErrorCode::InvalidResponse);
						}

						return plist;
					})
				.then([this](plist_t plist)
					{
						// Handle verification code response.
						return this->ProcessTwoFactorResponse<bool>(plist, [](auto plist) {
							auto node = plist_dict_get_item(plist, "ec");
							if (node)
							{
								uint64_t errorCode = 0;
								plist_get_uint_val(node, &errorCode);

								if (errorCode != 0)
								{
									throw APIError(APIErrorCode::InvalidResponse);
								}
							}

							return true;
						}, [=](auto resultCode) -> optional<APIError>
						{
							switch (resultCode)
							{
							case -21669:
								return std::make_optional<APIError>(APIErrorCode::IncorrectVerificationCode);

							default:
								return std::nullopt;
							}
						});
					});

			return task;
}

pplx::task<std::shared_ptr<Account>> AppleAPI::FetchAccount(std::shared_ptr<AppleAPISession> session)
{
	std::map<std::string, std::string> parameters = {};
	auto task = this->SendRequest("viewDeveloper.action", parameters, session, nullptr)
		.then([=](plist_t plist)->std::shared_ptr<Account>
		{	
			auto account = this->ProcessResponse<shared_ptr<Account>>(plist, [](auto plist)
				{
					auto node = plist_dict_get_item(plist, "developer");
					if (node == nullptr)
					{
						throw APIError(APIErrorCode::InvalidResponse);
					}

					auto account = make_shared<Account>(node);
					return account;

				}, [=](auto resultCode) -> optional<APIError>
				{
					return nullopt;
				});

			return account;
		});

	return task;
}

pplx::task<plist_t> AppleAPI::SendAuthenticationRequest(std::map<std::string, plist_t> requestParameters,
	std::shared_ptr<AnisetteData> anisetteData)
{
	auto header = plist_new_dict();
	plist_dict_set_item(header, "Version", plist_new_string("1.0.1"));

	auto requestDictionary = plist_new_dict();
	for (auto& parameter : requestParameters)
	{
		plist_dict_set_item(requestDictionary, parameter.first.c_str(), parameter.second);
	}

	std::map<std::string, plist_t> parameters = {
		{ "Header", header },
		{ "Request", requestDictionary }
	};

	auto plist = plist_new_dict();
	for (auto& parameter : parameters)
	{
		plist_dict_set_item(plist, parameter.first.c_str(), parameter.second);
	}

	char* plistXML = nullptr;
	uint32_t length = 0;
	plist_to_xml(plist, &plistXML, &length);

	std::map<utility::string_t, utility::string_t> headers = {
		{"Content-Type", "text/x-xml-plist"},
		{"X-Mme-Client-Info", (anisetteData->deviceDescription())},
		{"Accept", "*/*"},
		{"User-Agent", "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"}
	};

	uri_builder builder(U("/grandslam/GsService2"));

	http_request request(methods::POST);
	request.set_request_uri(builder.to_string());
	request.set_body(plistXML);

	for (auto& pair : headers)
	{
		if (request.headers().has(pair.first))
		{
			request.headers().remove(pair.first);
		}

		request.headers().add(pair.first, pair.second);
	}

	auto task = this->gsaClient().request(request)
		.then([=](http_response response)
			{
				return response.content_ready();
			})
		.then([=](http_response response)
			{
				odslog("Received auth response status code: " << response.status_code());
				return response.extract_vector();
			})
				.then([=](std::vector<unsigned char> compressedData)
					{
						std::vector<uint8_t> decompressedData = compressedData;

						std::string decompressedXML = std::string(decompressedData.begin(), decompressedData.end());

						plist_t plist = nullptr;
						plist_from_xml(decompressedXML.c_str(), (int)decompressedXML.size(), &plist);

						if (plist == nullptr)
						{
							throw APIError(APIErrorCode::InvalidResponse);
						}

						return plist;
					})
		.then([=](plist_t plist)
          {
				auto dictionary = plist_dict_get_item(plist, "Response");
				if (dictionary == NULL)
				{
					throw APIError(APIErrorCode::InvalidResponse);
				}

				auto statusNode = plist_dict_get_item(dictionary, "Status");
				if (statusNode == NULL)
				{
					throw APIError(APIErrorCode::InvalidResponse);
				}

				auto node = plist_dict_get_item(statusNode, "ec");
				int64_t resultCode = 0;
				
				auto type = plist_get_node_type(node);
				switch (type)
				{
				case PLIST_STRING:
				{
					char* value = nullptr;
					plist_get_string_val(node, &value);

					resultCode = atoi(value);
					break;
				}

				case PLIST_UINT:
				{
					uint64_t value = 0;
					plist_get_uint_val(node, &value);

					resultCode = (int64_t)value;
					break;
				}

				case PLIST_REAL:
				{
					double value = 0;
					plist_get_real_val(node, &value);

					resultCode = (int64_t)value;
					break;
				}

				default:
					break;
				}

				switch (resultCode)
				{
				case 0: return dictionary;
				case -29004: throw APIError(APIErrorCode::InvalidAnisetteData);
				default:
				{
					auto descriptionNode = plist_dict_get_item(statusNode, "em");
					if (descriptionNode == nullptr)
					{
						throw APIError(APIErrorCode::InvalidResponse);
					}

					char* errorDescription = nullptr;
					plist_get_string_val(descriptionNode, &errorDescription);

					if (errorDescription == nullptr)
					{
						throw APIError(APIErrorCode::InvalidResponse);
					}

					std::stringstream ss;
					ss << errorDescription << " (" << resultCode << ")";

					throw LocalizedError((int)resultCode, ss.str());
				}
				}
          });

		free(plistXML);
		plist_free(plist);

		return task;
}
