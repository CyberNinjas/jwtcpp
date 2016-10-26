#include "string.h"
#include "json.hpp"
#include "jwt.h"
#include "utils.h"
#include "exceptions.h"

#include "cryptopp/dsa.h"
#include "cryptopp/osrng.h"

using namespace std;
using namespace jwtcpp;
using namespace CryptoPP;

namespace jwtcpp {

    JWT::JWT(string algorithm, nlohmann::json payload, string signature,
             string signed_data)
    {
        this->algorithm = algorithm;
        this->payload = payload;
        this->signature = signature;
        this->signed_data = signed_data;
    }

    bool JWT::checkSignature(const string& key)
    {
        DSA::PublicKey publicKey;
        publicKey.Load(StringStore(key).Ref());

        DSA::Verifier verifier(publicKey);

        SignatureVerificationFilter svf(verifier);
        StringSource(this->signature +this->signed_data, true,
                     new Redirector(svf));

	    return svf.GetLastResult();
    }

     string JWT::getAlgorithm(){
      return algorithm;
     }
    nlohmann::json JWT::getPayload(){
      return payload;
      }

        JWT* parse(const string& jwt)
    {
        size_t pos;

        // extracting the algorithm, payload, signature and data
        char* tok = strtok((char*) jwt.c_str(), ".");
        string raw_algorithm = (string) tok;

        tok = strtok(NULL, ".");
        string raw_payload = (string) tok;

        tok = strtok(NULL, ".");
        string signature = (string) tok;

        string signed_data = raw_algorithm + "." + raw_payload;

        // decode json values for the algorithm and the payload
        string unparsed_header = decodeBase64(raw_algorithm);

        auto header = nlohmann::json::parse(unparsed_header);

        // check that the "alg" parameter is present. If not, throw an
        // exception
        string algorithm = header["alg"];
        if (algorithm.empty()){
            ParsingError e;
            throw e;
        }

        string unparsed_payload = decodeBase64(raw_payload);
        auto payload = nlohmann::json::parse(unparsed_payload);
        JWT* obj = new JWT(algorithm, payload, signature, signed_data);
        return obj;
    }

	string generate(const string& algorithm, const string& key,
                    map<string, string>* payloadMap)
    {
        // encode the algorithm in bytes
        json_t* jsonAlg = json_object();
        json_object_set(jsonAlg, "alg", json_string(algorithm.c_str()));
        string alg = encodeJSONBytes(jsonAlg);

        // loop on the payload map to create a json_object from it
        json_t* jsonPayload = json_object();

        if (payloadMap->size() > 0){
            map<string, string>::iterator iter;

            for(iter = payloadMap->begin(); iter != payloadMap->end(); iter++){
                json_object_set(jsonPayload, (*iter).first.c_str(),
                                json_string((*iter).second.c_str()));
            }

        }

        // encode the payload in bytes
        string payload = encodeJSONBytes(jsonPayload);

        // get a random number generator
        AutoSeededRandomPool rng;

        // sign the data with the key and the algorithm name.
        // XXX handle different algos
        DSA::PrivateKey privateKey;
        privateKey.Load(StringStore(key).Ref());

        DSA::Signer signer(privateKey);

        cout << alg + "." + payload << endl;

        string signature;
        StringSource(alg + "." + payload, true,
                     new SignerFilter(rng, signer, new StringSink(signature)));

        return alg + "." + payload + "." + signature;
    }
}
