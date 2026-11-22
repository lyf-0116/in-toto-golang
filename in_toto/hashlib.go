package in_toto

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"regexp"
)

// hashObjHexFormat matches the lowercase hexadecimal encoding produced by
// RecordArtifact (see fmt.Sprintf with the %x verb). Digest values declared
// in link metadata must use this format, because hash comparisons are exact
// string comparisons and uppercase digits would never match a runtime digest.
const hashObjHexFormat = "^[a-f0-9]+$"

var hashObjHexPattern = regexp.MustCompile(hashObjHexFormat)

// validateHashObj checks that every digest of an artifact hash object is
// non-empty and encoded as a lowercase hexadecimal string. It does not accept
// empty hash objects, because they carry no evidence about the artifact and
// must not satisfy MATCH rules.
func validateHashObj(artifactName string, hashes HashObj) error {
	if len(hashes) == 0 {
		return fmt.Errorf("artifact '%s' has no hashes", artifactName)
	}
	for algorithm, digest := range hashes {
		if digest == "" {
			return fmt.Errorf("artifact '%s' has an empty %s digest",
				artifactName, algorithm)
		}
		if !hashObjHexPattern.MatchString(digest) {
			return fmt.Errorf("artifact '%s' has an invalid %s digest: %s",
				artifactName, algorithm, digest)
		}
	}
	return nil
}

// hashObjsEqual reports whether two artifact hash objects provide matching
// evidence according to the in-toto specification.
//
// An empty hash object carries no evidence and therefore never matches, not
// even another empty hash object. Hash objects are considered equal if they
// share at least one hash algorithm for which the reported digests are equal,
// i.e. the algorithm sets do not have to be identical. Digests are compared
// exactly as lowercase hexadecimal strings, which is the encoding used when
// hashes are recorded at runtime; uppercase digests are rejected earlier by
// validateHashObj.
func hashObjsEqual(srcHashes, dstHashes HashObj) bool {
	if len(srcHashes) == 0 || len(dstHashes) == 0 {
		return false
	}
	// Iterate over the smaller map to keep the lookup cost minimal.
	hashesToCheck := srcHashes
	hashesToLookUp := dstHashes
	if len(dstHashes) < len(srcHashes) {
		hashesToCheck = dstHashes
		hashesToLookUp = srcHashes
	}
	for algorithm, digest := range hashesToCheck {
		otherDigest, exists := hashesToLookUp[algorithm]
		if exists && digest == otherDigest {
			return true
		}
	}
	return false
}

/*
getHashMapping returns a mapping from hash algorithm to supported hash
interface.
*/
func getHashMapping() map[string]func() hash.Hash {
	return map[string]func() hash.Hash{
		"sha256": sha256.New,
		"sha512": sha512.New,
		"sha384": sha512.New384,
	}
}

/*
hashToHex calculates the hash over data based on hash algorithm h.
*/
func hashToHex(h hash.Hash, data []byte) []byte {
	h.Write(data)
	// We need to use h.Sum(nil) here, because otherwise hash.Sum() appends
	// the hash to the passed data. So instead of having only the hash
	// we would get: "dataHASH"
	return h.Sum(nil)
}
