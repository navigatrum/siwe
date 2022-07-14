/**
 * This method is supposed to check if an address is conforming to EIP-55.
 * @param address Address to be checked if conforms with EIP-55.
 * @returns Either the return is or not in the EIP-55 format.
 */
export const isEIP55Address = (address: string) => {
    const createKeccakHash = require('keccak')
    const lowerAddress = `${address}`.toLowerCase().replace('0x', '')
    var hash = createKeccakHash('keccak256').update(lowerAddress).digest('hex')
    var ret = '0x'

    for (var i = 0; i < lowerAddress.length; i++) {
        if (parseInt(hash[i], 16) >= 8) {
            ret += lowerAddress[i].toUpperCase()
        } else {
            ret += lowerAddress[i]
        }
    }
    return address === ret;
}

/**
 * Validates `issuedAt`, `expirationTime` and `notBefore` object props against ISO-8601 time.
 * @param obj Abnf `ParsedMessage` or `SiweMessage` to be checked.
 * @param errorMsg The error message to be thrown when validation fails.
 */
export const validateTimeProps = (obj: any, errorMsg = 'Invalid time format.') => {
    const ISO8601 =
        /([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))/;

    ['issuedAt', 'expirationTime', 'notBefore'].forEach(prop => {
        if (prop in obj && !ISO8601.test(obj.prop)) {
            throw new Error(errorMsg);
        }
    });
}
