const openpgp = require('openpgp');

const field = document.querySelectorAll('textarea[data-encrypt="data-encrypt"]')[0];
const form = field.closest('form');
const domain = new URL(window.location.href);
const securitytxtknown = `${domain.origin}/.well-known/security.txt`;
const securitytxtunknown = `${domain.origin}/security.txt`;
const request = new XMLHttpRequest();
// from https://regexr.com/2rhq7
const reg = /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/g;

// This variable is to bypass IE's lack of support for request.responseURL
// Yep, an IE fix in 2019, who would've thought
let isWellKnown = true;

const submitForm = () => {
  field.removeAttribute('disabled');
  form.submit();
  return true;
};

const encryptField = (armoredPubkey) => {
  if (armoredPubkey) {
    openpgp.key.readArmored(armoredPubkey).then((key) => {
      const message = {
        message: openpgp.message.fromText(field.value),
        publicKeys: [key.keys[0]],
      };
      openpgp.encrypt(message).then((result) => {
        field.removeAttribute('disabled');

        field.value = result.data;
        return submitForm();
      });
    });
  } else {
    return submitForm();
  }
};

const getKey = (HKP) => {
  if (request.status >= 200 && request.status < 300) {
    const address = request.responseText.match(reg);
    const hkp = new openpgp.HKP(HKP); // Defaults to https://keyserver.ubuntu.com, or pass another keyserver URL as a string

    const options = {
      query: address,
    };

    return hkp.lookup(options);
  } else {
    // If the previous request was the .well-known folder, try the root
    if (isWellKnown) {
      // Make sure the previous request is completely done for
      request.abort();
      isWellKnown = false;
      createRequest(securitytxtunknown);
    } else {
      // Otherwise, let's just continue submitting :(
      return submitForm();
    }
  }
};

const createRequest = (url) => {
  request.open('GET', url, true);
  request.send(null);
};

export default function (HKP = null) {
  form.addEventListener('submit', (e) => {
    if (!window.crypto.getRandomValues) {
      // eslint-disable-next-line no-alert
      window.alert('Your browser does not support PGP, your email will not be encrypted');
    } else {
      field.setAttribute('disabled', 'disabled');
      e.preventDefault();
      createRequest(securitytxtknown);
      request.onreadystatechange = () => {
        // getKey is only "defined" if it returns a promise, so that needs a check
        if (request.readyState === 4 && typeof getKey() !== "undefined") {
          return getKey(HKP)
            .then((armoredPubkey) => {
              return encryptField(armoredPubkey);
            });
        }
      };
    }
  });
};
