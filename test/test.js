'use strict';

const expect = require('chai').expect;
const mod = require('../index');

describe('nrghash', function() {
    it('should gen value', function(){
        const res = mod.nrghash(
            Buffer.from(''),
            1,
            '0x1111111111111111111111111111111111111111111111111111111111111111',
            '0x2222222222222222222222222222222222222222222222222222222222222222',
            1541177067,
            0x207fffff,
            30000,
            '0x3333333333333333333333333333333333333333333333333333333333333333',
            123
        );

        const value = Buffer.from('f92f77cb750f64932a34f014ae07fd937f61e6b5a314f2cbf5f1a6d1e4808ccf', 'hex');
        expect(res).to.eql(value);
    });

    it('should gen block hash', function(){
        const res = mod.blockhash(
            Buffer.from(''),
            1,
            '0x1111111111111111111111111111111111111111111111111111111111111111',
            '0x2222222222222222222222222222222222222222222222222222222222222222',
            1541177067,
            0x207fffff,
            30000,
            '0x3333333333333333333333333333333333333333333333333333333333333333',
            123
        );

        const hash = Buffer.from('b7cc64bdcd0c66c6c53157e426585a6295922d004cedccd0c39244d7fc187835', 'hex');
        expect(res).to.eql(hash);
    });
});
