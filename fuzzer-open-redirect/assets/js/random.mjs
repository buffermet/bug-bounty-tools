/**
 * Random module.
 */

const module = {
    charsAlphabeticLowerCase: ['abcdefghijklmnopqrstuvwxyz'],
    charsAlphabeticUpperCase: ['ABCDEFGHIJKLMNOPQRSTUVWXYZ'],
    charsNumeric: ['0123456789'],
    /**
     * Returns a random alphabetic string of a given length, or false.
     * @param {Number} length - Length of the string.
     * @returns {string|false}
     */
    alphabeticString: length => {
        return module.string(
            module.charsAlphabeticLowerCase
                + module.charsAlphabeticUpperCase,
            length)
    },
    /**
     * Returns a random alphanumeric string of a given length, or false.
     * @param {Number} length - Length of the string.
     * @returns {string|false}
     */
    alphanumericString: length => {
        return module.string(
            module.charsAlphabeticLowerCase
                + module.charsAlphabeticUpperCase
                + module.charsNumeric,
            length)
    },
    string: (chars, length) => {
        const buffer = ''
        for (let a = 0; a !== length; a++) {
            buffer += chars[Math.floor(Math.random() * chars.length)]
        }
        return buffer
    },
}

Object.freeze(module)

export default module
