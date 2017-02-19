//
// Copyright (C) 2015-2016  Markus Hiienkari <mhiienka@niksula.hut.fi>
//
// This file is part of Open Source Scan Converter project.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

`define FT_A                    0
`define FT_B                    1
`define FT_C                    2
`define FT_D                    3
`define FT_E                    4
`define FT_F                    5
`define FT_G                    6
`define FT_H                    7
`define FT_I                    8

`define FILTER_STAGES           4

module filter (
    input pclk_act,

    input [1:0] mode,
    input [2:0] str,
    input [2:0] col,
    input [2:0] row,

    input [23:0] prev_in,
    input [23:0] curr_in,
    input [23:0] next_in,
    input hsync_in,
    input vsync_in,
    input dataenable_in,

    output reg [23:0] data_out,
    output reg hsync_out,
    output reg vsync_out,
    output reg dataenable_out,
    output reg [2:0] col_out,
    output reg [2:0] row_out,

    input reset_n    
);

// wire definitions
wire hsync_f0;
wire vsync_f0;
wire dataenable_f0;

reg [23:0] matrix_f0[9];

assign hsync_f0 = hsync_in;
assign vsync_f0 = vsync_in;
assign dataenable_f0 = dataenable_in;

`define CMP_DELTA 32
`define DISTANCE_DELTA 8

function cmp;
    input [23:0] a;
    input [23:0] b;
    input eq;
    reg [7:0] a_r, a_g, a_b;
    reg [7:0] b_r, b_g, b_b;
    reg ret;
    
    begin
        { a_r, a_b, a_g } = a;
        { b_r, b_b, b_g } = b;

        ret = (((a_r >= b_r) ? a_r - b_r : b_r - a_r) < `CMP_DELTA) && (((a_b >= b_b) ? a_b - b_b : b_b - a_b) < `CMP_DELTA) && (((a_g >= b_g) ? a_g - b_g : b_g - a_g) < `CMP_DELTA);
        //ret = (((a_r >= b_r) ? a_r - b_r : b_r - a_r) < 16) && (((a_b >= b_b) ? a_b - b_b : b_b - a_b) < 16) && (((a_g >= b_g) ? a_g - b_g : b_g - a_g) < 16);
        //ret = (a_r[7:5] == b_r[7:5]) && (a_g[7:5] == b_g[7:5]) && (a_b[7:5] == b_b[7:5]);
    
        if (eq == 1)
            cmp = ret;
        else
            cmp = !ret;            
    end
    endfunction

function cmp_dist;
    input [23:0] a;
    input [23:0] b;

    reg [7:0] a_r, a_g, a_b;
    reg [7:0] b_r, b_g, b_b;
    
    begin
        { a_r, a_b, a_g } = a;
        { b_r, b_b, b_g } = b;

        cmp_dist = (`CMP_DELTA - ((a_r >= b_r) ? a_r - b_r : b_r - a_r) < `DISTANCE_DELTA) || (`CMP_DELTA - ((a_b >= b_b) ? a_b - b_b : b_b - a_b) < `DISTANCE_DELTA) || (`CMP_DELTA - ((a_g >= b_g) ? a_g - b_g : b_g - a_g) < `DISTANCE_DELTA);
    end
    endfunction

    
function [23:0] lerp;
    input [23:0] a;
    input [23:0] b;
    input [2:0] l;
    
    reg [7:0] a_r, a_g, a_b;
    reg[7:0] b_r, b_g, b_b;
    
    begin
        // TODO: fix rgb order.  G is reversed with B in both places so it ends up working.
        { a_r, a_b, a_g } = a;
        { b_r, b_b, b_g } = b;

        case (l)
            0: lerp = ((1*(a_r>>1) + 1*(a_r>>2) + 1*(a_r>>3) + 0*(b_r>>1) + 0*(b_r>>2) + 1*(b_r>>3)) << 16) | ((1*(a_b>>1) + 1*(a_b>>2) + 1*(a_b>>3) + 0*(b_b>>1) + 0*(b_b>>2) + 1*(b_b>>3)) << 8) | ((1*(a_g>>1) + 1*(a_g>>2) + 1*(a_g>>3) + 0*(b_g>>1) + 0*(b_g>>2) + 1*(b_g>>3)) << 0);
            1: lerp = ((1*(a_r>>1) + 1*(a_r>>2) + 0*(a_r>>3) + 0*(b_r>>1) + 1*(b_r>>2) + 0*(b_r>>3)) << 16) | ((1*(a_b>>1) + 1*(a_b>>2) + 0*(a_b>>3) + 0*(b_b>>1) + 1*(b_b>>2) + 0*(b_b>>3)) << 8) | ((1*(a_g>>1) + 1*(a_g>>2) + 0*(a_g>>3) + 0*(b_g>>1) + 1*(b_g>>2) + 0*(b_g>>3)) << 0);
            2: lerp = ((1*(a_r>>1) + 0*(a_r>>2) + 1*(a_r>>3) + 0*(b_r>>1) + 1*(b_r>>2) + 1*(b_r>>3)) << 16) | ((1*(a_b>>1) + 0*(a_b>>2) + 1*(a_b>>3) + 0*(b_b>>1) + 1*(b_b>>2) + 1*(b_b>>3)) << 8) | ((1*(a_g>>1) + 0*(a_g>>2) + 1*(a_g>>3) + 0*(b_g>>1) + 1*(b_g>>2) + 1*(b_g>>3)) << 0);
            3: lerp = ((1*(a_r>>1) + 0*(a_r>>2) + 0*(a_r>>3) + 1*(b_r>>1) + 0*(b_r>>2) + 0*(b_r>>3)) << 16) | ((1*(a_b>>1) + 0*(a_b>>2) + 0*(a_b>>3) + 1*(b_b>>1) + 0*(b_b>>2) + 0*(b_b>>3)) << 8) | ((1*(a_g>>1) + 0*(a_g>>2) + 0*(a_g>>3) + 1*(b_g>>1) + 0*(b_g>>2) + 0*(b_g>>3)) << 0);
            4: lerp = ((0*(a_r>>1) + 1*(a_r>>2) + 1*(a_r>>3) + 1*(b_r>>1) + 0*(b_r>>2) + 1*(b_r>>3)) << 16) | ((0*(a_b>>1) + 1*(a_b>>2) + 1*(a_b>>3) + 1*(b_b>>1) + 0*(b_b>>2) + 1*(b_b>>3)) << 8) | ((0*(a_g>>1) + 1*(a_g>>2) + 1*(a_g>>3) + 1*(b_g>>1) + 0*(b_g>>2) + 1*(b_g>>3)) << 0);
            5: lerp = ((0*(a_r>>1) + 1*(a_r>>2) + 0*(a_r>>3) + 1*(b_r>>1) + 1*(b_r>>2) + 0*(b_r>>3)) << 16) | ((0*(a_b>>1) + 1*(a_b>>2) + 0*(a_b>>3) + 1*(b_b>>1) + 1*(b_b>>2) + 0*(b_b>>3)) << 8) | ((0*(a_g>>1) + 1*(a_g>>2) + 0*(a_g>>3) + 1*(b_g>>1) + 1*(b_g>>2) + 0*(b_g>>3)) << 0);
            6: lerp = ((0*(a_r>>1) + 0*(a_r>>2) + 1*(a_r>>3) + 1*(b_r>>1) + 1*(b_r>>2) + 1*(b_r>>3)) << 16) | ((0*(a_b>>1) + 0*(a_b>>2) + 1*(a_b>>3) + 1*(b_b>>1) + 1*(b_b>>2) + 1*(b_b>>3)) << 8) | ((0*(a_g>>1) + 0*(a_g>>2) + 1*(a_g>>3) + 1*(b_g>>1) + 1*(b_g>>2) + 1*(b_g>>3)) << 0);
            7: lerp = b;
            default: lerp = a;
        endcase
    end
    endfunction

function pixel_diff;
    input [23:0] a;
    input [23:0] b;
    
    // reg [5:0] r_diff, g_diff, b_diff;
    // reg [6:0] t;
    // reg [7:0] y;
    // reg [6:0] u;
    // reg [7:0] v;

    reg [7:0] r_diff, g_diff, b_diff;
    reg [7:0] t;
    reg [7:0] y;
    reg [7:0] u;
    reg [7:0] v;
    
    reg y_inside, u_inside, v_inside;
    
    begin
        r_diff = ({a[23], a[23], a[23:18]}) - ({b[23], b[23], b[23:18]});
        g_diff = ({a[15], a[15], a[15:10]}) - ({b[15], b[15], b[15:10]});
        b_diff = ({a[ 7], a[ 7], a[ 7: 2]}) - ({b[ 7], b[ 7], b[ 7: 2]});
        // temporarily remove small changes... could also reduce differences by 32 like scale
        //r_diff = ({a[23], a[23], a[23:20], 2'b00}) - ({b[23], b[23], b[23:20], 2'b00});
        //g_diff = ({a[15], a[15], a[15:12], 2'b00}) - ({b[15], b[15], b[15:12], 2'b00});
        //b_diff = ({a[ 7], a[ 7], a[ 7: 4], 2'b00}) - ({b[ 7], b[ 7], b[ 7: 4], 2'b00});
        
        t = (r_diff) + (b_diff);
        // YUV approximation
        y = (t) + (g_diff);
        u = (r_diff) - (b_diff);
        v = ({g_diff[7], g_diff[5:0], 1'b0}) - (t);
        
        y_inside = (y < 8'h18 || y > 8'he8);
        u_inside = (u < 8'h4  || u > 8'hfc);
        v_inside = (v < 8'h6  || v > 8'hfa);
        
        pixel_diff = (y_inside && u_inside && v_inside) ? 1'b0 : 1'b1;
    end
    endfunction
    
function [7:0] InnerBlend(input [8:0] Op, input [7:0] A, input [7:0] B, input [7:0] C);
    reg OpOnes;
    reg [10:0] Amul;
    reg [9:0] Bmul;
    reg [9:0] Cmul;
    reg [10:0] At;
    reg [10:0] Bt;
    reg [10:0] Ct;
    reg [11:0] Res;

    begin
        OpOnes = Op[4];
        Amul = A * Op[7:5];
        Bmul = B * Op[3:2];
        Cmul = C * Op[1:0];
        At =  Amul;
        Bt = (OpOnes == 0) ? {Bmul, 1'b0} : {3'b0, B};
        Ct = (OpOnes == 0) ? {Cmul, 1'b0} : {3'b0, C};
        Res = {At, 1'b0} + Bt + Ct;
        InnerBlend = Op[8] ? A : Res[11:4];
    end
endfunction

function [23:0] FinalBlend(input [8:0] op, input [1:0] input_ctrl, input [23:0] E, input [23:0] A, input [23:0] B, input [23:0] D);
    reg [23:0] Input1;
    reg [23:0] Input2;
    reg [23:0] Input3;

    begin
        // Generate inputs to the inner blender. Valid combinations.
        // 00: E A B
        // 01: E A D 
        // 10: E D B
        // 11: E B D
        Input1 = E;
        Input2 = !input_ctrl[1] ? A :
                 !input_ctrl[0] ? D : B;
        Input3 = !input_ctrl[0] ? B : D;
        FinalBlend = { InnerBlend(op, Input1[23:16], Input2[23:16], Input3[23:16]),
                       InnerBlend(op, Input1[15:8],  Input2[15:8],  Input3[15:8]),
                       InnerBlend(op, Input1[7:0],   Input2[7:0],   Input3[7:0]) };
    end

endfunction

function [10:0] BlendCtrl(input [5:0] rule, input disable_hq2x, input [23:0] E, input [23:0] A, input [23:0] B, input [23:0] D, input [23:0] F, input [23:0] H);
    reg [1:0] input_ctrl;
    reg [8:0] op;
    localparam BLEND0 = 9'b1_xxx_x_xx_xx; // 0: A
    localparam BLEND1 = 9'b0_110_0_10_00; // 1: (A * 12 + B * 4) >> 4
    localparam BLEND2 = 9'b0_100_0_10_10; // 2: (A * 8 + B * 4 + C * 4) >> 4
    localparam BLEND3 = 9'b0_101_0_10_01; // 3: (A * 10 + B * 4 + C * 2) >> 4
    localparam BLEND4 = 9'b0_110_0_01_01; // 4: (A * 12 + B * 2 + C * 2) >> 4
    localparam BLEND5 = 9'b0_010_0_11_11; // 5: (A * 4 + (B + C) * 6) >> 4
    localparam BLEND6 = 9'b0_111_1_xx_xx; // 6: (A * 14 + B + C) >> 4
    localparam AB = 2'b00;
    localparam AD = 2'b01;
    localparam DB = 2'b10;
    localparam BD = 2'b11;
    reg is_diff;
    
    reg [23:0] Input1;
    reg [23:0] Input2;
    reg [23:0] Input3;

    begin   
        is_diff = pixel_diff(rule[1] ? B : H, rule[0] ? D : F);

        case({!is_diff, rule[5:2]})
            0,16:  {op, input_ctrl} = {BLEND0, 2'bxx}; // 3x
            1,17:  {op, input_ctrl} = {BLEND1, AB};
            2,18:  {op, input_ctrl} = {BLEND1, DB};
            3,19:  {op, input_ctrl} = {BLEND1, BD};
            4,20:  {op, input_ctrl} = {BLEND2, DB};
            5,21:  {op, input_ctrl} = {BLEND2, AB};
            6,22:  {op, input_ctrl} = {BLEND2, AD};

            7: {op, input_ctrl} = {BLEND0, 2'bxx}; // 3x
            8: {op, input_ctrl} = {BLEND0, 2'bxx};
            9: {op, input_ctrl} = {BLEND0, 2'bxx};
            10: {op, input_ctrl} = {BLEND0, 2'bxx};
            11: {op, input_ctrl} = {BLEND1, AB};
            12: {op, input_ctrl} = {BLEND1, AB};
            13: {op, input_ctrl} = {BLEND1, AB};
            14: {op, input_ctrl} = {BLEND1, DB};
            15: {op, input_ctrl} = {BLEND1, BD};

            23: {op, input_ctrl} = {BLEND1, BD}; // 3x
            24: {op, input_ctrl} = {BLEND2, DB};
            25: {op, input_ctrl} = {BLEND5, DB};
            26: {op, input_ctrl} = {BLEND6, DB};
            27: {op, input_ctrl} = {BLEND2, DB};
            28: {op, input_ctrl} = {BLEND4, DB};
            29: {op, input_ctrl} = {BLEND5, DB};
            30: {op, input_ctrl} = {BLEND3, BD};
            31: {op, input_ctrl} = {BLEND3, DB};
            default: {op, input_ctrl} = 11'bx;
        endcase
        
        // Setting op[8] effectively disables HQ2X because blend will always return E.
        if (disable_hq2x)
            op[8] = 1;
        
        BlendCtrl = {op, input_ctrl};
    end
endfunction

// HQX tables
reg [5:0] hqTable[0:255];
initial begin
    hqTable[0] = 19; hqTable[1] = 19; hqTable[2] = 26; hqTable[3] = 11;
    hqTable[4] = 19; hqTable[5] = 19; hqTable[6] = 26; hqTable[7] = 11;
    hqTable[8] = 23; hqTable[9] = 15; hqTable[10] = 47; hqTable[11] = 35;
    hqTable[12] = 23; hqTable[13] = 15; hqTable[14] = 55; hqTable[15] = 39;
    hqTable[16] = 19; hqTable[17] = 19; hqTable[18] = 26; hqTable[19] = 58;
    hqTable[20] = 19; hqTable[21] = 19; hqTable[22] = 26; hqTable[23] = 58;
    hqTable[24] = 23; hqTable[25] = 15; hqTable[26] = 35; hqTable[27] = 35;
    hqTable[28] = 23; hqTable[29] = 15; hqTable[30] = 7; hqTable[31] = 35;
    hqTable[32] = 19; hqTable[33] = 19; hqTable[34] = 26; hqTable[35] = 11;
    hqTable[36] = 19; hqTable[37] = 19; hqTable[38] = 26; hqTable[39] = 11;
    hqTable[40] = 23; hqTable[41] = 15; hqTable[42] = 55; hqTable[43] = 39;
    hqTable[44] = 23; hqTable[45] = 15; hqTable[46] = 51; hqTable[47] = 43;
    hqTable[48] = 19; hqTable[49] = 19; hqTable[50] = 26; hqTable[51] = 58;
    hqTable[52] = 19; hqTable[53] = 19; hqTable[54] = 26; hqTable[55] = 58;
    hqTable[56] = 23; hqTable[57] = 15; hqTable[58] = 51; hqTable[59] = 35;
    hqTable[60] = 23; hqTable[61] = 15; hqTable[62] = 7; hqTable[63] = 43;
    hqTable[64] = 19; hqTable[65] = 19; hqTable[66] = 26; hqTable[67] = 11;
    hqTable[68] = 19; hqTable[69] = 19; hqTable[70] = 26; hqTable[71] = 11;
    hqTable[72] = 23; hqTable[73] = 61; hqTable[74] = 35; hqTable[75] = 35;
    hqTable[76] = 23; hqTable[77] = 61; hqTable[78] = 51; hqTable[79] = 35;
    hqTable[80] = 19; hqTable[81] = 19; hqTable[82] = 26; hqTable[83] = 11;
    hqTable[84] = 19; hqTable[85] = 19; hqTable[86] = 26; hqTable[87] = 11;
    hqTable[88] = 23; hqTable[89] = 15; hqTable[90] = 51; hqTable[91] = 35;
    hqTable[92] = 23; hqTable[93] = 15; hqTable[94] = 51; hqTable[95] = 35;
    hqTable[96] = 19; hqTable[97] = 19; hqTable[98] = 26; hqTable[99] = 11;
    hqTable[100] = 19; hqTable[101] = 19; hqTable[102] = 26; hqTable[103] = 11;
    hqTable[104] = 23; hqTable[105] = 61; hqTable[106] = 7; hqTable[107] = 35;
    hqTable[108] = 23; hqTable[109] = 61; hqTable[110] = 7; hqTable[111] = 43;
    hqTable[112] = 19; hqTable[113] = 19; hqTable[114] = 26; hqTable[115] = 11;
    hqTable[116] = 19; hqTable[117] = 19; hqTable[118] = 26; hqTable[119] = 58;
    hqTable[120] = 23; hqTable[121] = 15; hqTable[122] = 51; hqTable[123] = 35;
    hqTable[124] = 23; hqTable[125] = 61; hqTable[126] = 7; hqTable[127] = 43;
    hqTable[128] = 19; hqTable[129] = 19; hqTable[130] = 26; hqTable[131] = 11;
    hqTable[132] = 19; hqTable[133] = 19; hqTable[134] = 26; hqTable[135] = 11;
    hqTable[136] = 23; hqTable[137] = 15; hqTable[138] = 47; hqTable[139] = 35;
    hqTable[140] = 23; hqTable[141] = 15; hqTable[142] = 55; hqTable[143] = 39;
    hqTable[144] = 19; hqTable[145] = 19; hqTable[146] = 26; hqTable[147] = 11;
    hqTable[148] = 19; hqTable[149] = 19; hqTable[150] = 26; hqTable[151] = 11;
    hqTable[152] = 23; hqTable[153] = 15; hqTable[154] = 51; hqTable[155] = 35;
    hqTable[156] = 23; hqTable[157] = 15; hqTable[158] = 51; hqTable[159] = 35;
    hqTable[160] = 19; hqTable[161] = 19; hqTable[162] = 26; hqTable[163] = 11;
    hqTable[164] = 19; hqTable[165] = 19; hqTable[166] = 26; hqTable[167] = 11;
    hqTable[168] = 23; hqTable[169] = 15; hqTable[170] = 55; hqTable[171] = 39;
    hqTable[172] = 23; hqTable[173] = 15; hqTable[174] = 51; hqTable[175] = 43;
    hqTable[176] = 19; hqTable[177] = 19; hqTable[178] = 26; hqTable[179] = 11;
    hqTable[180] = 19; hqTable[181] = 19; hqTable[182] = 26; hqTable[183] = 11;
    hqTable[184] = 23; hqTable[185] = 15; hqTable[186] = 51; hqTable[187] = 39;
    hqTable[188] = 23; hqTable[189] = 15; hqTable[190] = 7; hqTable[191] = 43;
    hqTable[192] = 19; hqTable[193] = 19; hqTable[194] = 26; hqTable[195] = 11;
    hqTable[196] = 19; hqTable[197] = 19; hqTable[198] = 26; hqTable[199] = 11;
    hqTable[200] = 23; hqTable[201] = 15; hqTable[202] = 51; hqTable[203] = 35;
    hqTable[204] = 23; hqTable[205] = 15; hqTable[206] = 51; hqTable[207] = 39;
    hqTable[208] = 19; hqTable[209] = 19; hqTable[210] = 26; hqTable[211] = 11;
    hqTable[212] = 19; hqTable[213] = 19; hqTable[214] = 26; hqTable[215] = 11;
    hqTable[216] = 23; hqTable[217] = 15; hqTable[218] = 51; hqTable[219] = 35;
    hqTable[220] = 23; hqTable[221] = 15; hqTable[222] = 7; hqTable[223] = 35;
    hqTable[224] = 19; hqTable[225] = 19; hqTable[226] = 26; hqTable[227] = 11;
    hqTable[228] = 19; hqTable[229] = 19; hqTable[230] = 26; hqTable[231] = 11;
    hqTable[232] = 23; hqTable[233] = 15; hqTable[234] = 51; hqTable[235] = 35;
    hqTable[236] = 23; hqTable[237] = 15; hqTable[238] = 7; hqTable[239] = 43;
    hqTable[240] = 19; hqTable[241] = 19; hqTable[242] = 26; hqTable[243] = 11;
    hqTable[244] = 19; hqTable[245] = 19; hqTable[246] = 26; hqTable[247] = 11;
    hqTable[248] = 23; hqTable[249] = 15; hqTable[250] = 7; hqTable[251] = 35;
    hqTable[252] = 23; hqTable[253] = 15; hqTable[254] = 7; hqTable[255] = 43;
end

reg [5:0] hqTable3x[0:255];
initial begin
    hqTable3x[0] = 12; hqTable3x[1] = 12; hqTable3x[2] = 0; hqTable3x[3] = 0;
    hqTable3x[4] = 12; hqTable3x[5] = 12; hqTable3x[6] = 0; hqTable3x[7] = 0;
    hqTable3x[8] = 12; hqTable3x[9] = 12; hqTable3x[10] = 41; hqTable3x[11] = 41;
    hqTable3x[12] = 12; hqTable3x[13] = 12; hqTable3x[14] = 39; hqTable3x[15] = 39;
    hqTable3x[16] = 12; hqTable3x[17] = 12; hqTable3x[18] = 42; hqTable3x[19] = 38;
    hqTable3x[20] = 12; hqTable3x[21] = 12; hqTable3x[22] = 42; hqTable3x[23] = 38;
    hqTable3x[24] = 12; hqTable3x[25] = 12; hqTable3x[26] = 0; hqTable3x[27] = 41;
    hqTable3x[28] = 12; hqTable3x[29] = 12; hqTable3x[30] = 42; hqTable3x[31] = 0;
    hqTable3x[32] = 12; hqTable3x[33] = 12; hqTable3x[34] = 0; hqTable3x[35] = 0;
    hqTable3x[36] = 12; hqTable3x[37] = 12; hqTable3x[38] = 0; hqTable3x[39] = 0;
    hqTable3x[40] = 12; hqTable3x[41] = 12; hqTable3x[42] = 31; hqTable3x[43] = 31;
    hqTable3x[44] = 12; hqTable3x[45] = 12; hqTable3x[46] = 0; hqTable3x[47] = 0;
    hqTable3x[48] = 12; hqTable3x[49] = 12; hqTable3x[50] = 42; hqTable3x[51] = 38;
    hqTable3x[52] = 12; hqTable3x[53] = 12; hqTable3x[54] = 42; hqTable3x[55] = 38;
    hqTable3x[56] = 12; hqTable3x[57] = 12; hqTable3x[58] = 0; hqTable3x[59] = 41;
    hqTable3x[60] = 12; hqTable3x[61] = 12; hqTable3x[62] = 42; hqTable3x[63] = 0;
    hqTable3x[64] = 12; hqTable3x[65] = 12; hqTable3x[66] = 0; hqTable3x[67] = 0;
    hqTable3x[68] = 12; hqTable3x[69] = 12; hqTable3x[70] = 0; hqTable3x[71] = 0;
    hqTable3x[72] = 12; hqTable3x[73] = 12; hqTable3x[74] = 41; hqTable3x[75] = 41;
    hqTable3x[76] = 12; hqTable3x[77] = 12; hqTable3x[78] = 0; hqTable3x[79] = 41;
    hqTable3x[80] = 12; hqTable3x[81] = 12; hqTable3x[82] = 42; hqTable3x[83] = 0;
    hqTable3x[84] = 12; hqTable3x[85] = 12; hqTable3x[86] = 42; hqTable3x[87] = 42;
    hqTable3x[88] = 12; hqTable3x[89] = 12; hqTable3x[90] = 0; hqTable3x[91] = 41;
    hqTable3x[92] = 12; hqTable3x[93] = 12; hqTable3x[94] = 42; hqTable3x[95] = 0;
    hqTable3x[96] = 12; hqTable3x[97] = 12; hqTable3x[98] = 0; hqTable3x[99] = 0;
    hqTable3x[100] = 12; hqTable3x[101] = 12; hqTable3x[102] = 0; hqTable3x[103] = 0;
    hqTable3x[104] = 12; hqTable3x[105] = 12; hqTable3x[106] = 0; hqTable3x[107] = 41;
    hqTable3x[108] = 12; hqTable3x[109] = 12; hqTable3x[110] = 0; hqTable3x[111] = 0;
    hqTable3x[112] = 12; hqTable3x[113] = 12; hqTable3x[114] = 0; hqTable3x[115] = 0;
    hqTable3x[116] = 12; hqTable3x[117] = 12; hqTable3x[118] = 42; hqTable3x[119] = 38;
    hqTable3x[120] = 12; hqTable3x[121] = 12; hqTable3x[122] = 0; hqTable3x[123] = 41;
    hqTable3x[124] = 12; hqTable3x[125] = 12; hqTable3x[126] = 42; hqTable3x[127] = 41;
    hqTable3x[128] = 12; hqTable3x[129] = 12; hqTable3x[130] = 0; hqTable3x[131] = 0;
    hqTable3x[132] = 12; hqTable3x[133] = 12; hqTable3x[134] = 0; hqTable3x[135] = 0;
    hqTable3x[136] = 12; hqTable3x[137] = 12; hqTable3x[138] = 41; hqTable3x[139] = 41;
    hqTable3x[140] = 12; hqTable3x[141] = 12; hqTable3x[142] = 39; hqTable3x[143] = 39;
    hqTable3x[144] = 12; hqTable3x[145] = 12; hqTable3x[146] = 30; hqTable3x[147] = 0;
    hqTable3x[148] = 12; hqTable3x[149] = 12; hqTable3x[150] = 30; hqTable3x[151] = 0;
    hqTable3x[152] = 12; hqTable3x[153] = 12; hqTable3x[154] = 0; hqTable3x[155] = 41;
    hqTable3x[156] = 12; hqTable3x[157] = 12; hqTable3x[158] = 42; hqTable3x[159] = 0;
    hqTable3x[160] = 12; hqTable3x[161] = 12; hqTable3x[162] = 0; hqTable3x[163] = 0;
    hqTable3x[164] = 12; hqTable3x[165] = 12; hqTable3x[166] = 0; hqTable3x[167] = 0;
    hqTable3x[168] = 12; hqTable3x[169] = 12; hqTable3x[170] = 31; hqTable3x[171] = 31;
    hqTable3x[172] = 12; hqTable3x[173] = 12; hqTable3x[174] = 0; hqTable3x[175] = 0;
    hqTable3x[176] = 12; hqTable3x[177] = 12; hqTable3x[178] = 30; hqTable3x[179] = 0;
    hqTable3x[180] = 12; hqTable3x[181] = 12; hqTable3x[182] = 30; hqTable3x[183] = 0;
    hqTable3x[184] = 12; hqTable3x[185] = 12; hqTable3x[186] = 0; hqTable3x[187] = 31;
    hqTable3x[188] = 12; hqTable3x[189] = 12; hqTable3x[190] = 30; hqTable3x[191] = 0;
    hqTable3x[192] = 12; hqTable3x[193] = 12; hqTable3x[194] = 0; hqTable3x[195] = 0;
    hqTable3x[196] = 12; hqTable3x[197] = 12; hqTable3x[198] = 0; hqTable3x[199] = 0;
    hqTable3x[200] = 12; hqTable3x[201] = 12; hqTable3x[202] = 0; hqTable3x[203] = 41;
    hqTable3x[204] = 12; hqTable3x[205] = 12; hqTable3x[206] = 0; hqTable3x[207] = 39;
    hqTable3x[208] = 12; hqTable3x[209] = 12; hqTable3x[210] = 0; hqTable3x[211] = 0;
    hqTable3x[212] = 12; hqTable3x[213] = 12; hqTable3x[214] = 42; hqTable3x[215] = 0;
    hqTable3x[216] = 12; hqTable3x[217] = 12; hqTable3x[218] = 0; hqTable3x[219] = 41;
    hqTable3x[220] = 12; hqTable3x[221] = 12; hqTable3x[222] = 42; hqTable3x[223] = 42;
    hqTable3x[224] = 12; hqTable3x[225] = 12; hqTable3x[226] = 0; hqTable3x[227] = 0;
    hqTable3x[228] = 12; hqTable3x[229] = 12; hqTable3x[230] = 0; hqTable3x[231] = 0;
    hqTable3x[232] = 12; hqTable3x[233] = 12; hqTable3x[234] = 0; hqTable3x[235] = 41;
    hqTable3x[236] = 12; hqTable3x[237] = 12; hqTable3x[238] = 0; hqTable3x[239] = 0;
    hqTable3x[240] = 12; hqTable3x[241] = 12; hqTable3x[242] = 0; hqTable3x[243] = 0;
    hqTable3x[244] = 12; hqTable3x[245] = 12; hqTable3x[246] = 42; hqTable3x[247] = 0;
    hqTable3x[248] = 12; hqTable3x[249] = 12; hqTable3x[250] = 0; hqTable3x[251] = 41;
    hqTable3x[252] = 12; hqTable3x[253] = 12; hqTable3x[254] = 42; hqTable3x[255] = 0;
end

// reg definitions
reg [23:0] prev_m1, prev_m2;
reg [23:0] curr_m1, curr_m2;
reg [23:0] next_m1, next_m2;

// pass through
reg hsync_f[`FILTER_STAGES];
reg vsync_f[`FILTER_STAGES];
reg dataenable_f[`FILTER_STAGES];

// scale
reg [23:0] scale_o[3][3], scale_o_d1[3][3], scale_col_o[3];
reg scalecond_f1;
reg cmp_DB1_f1, cmp_DB1_EC0_f1, cmp_BF1_EA0_f1, cmp_BF1_f1, cmp_DB1_EG0_f1, cmp_DH1_EA0_f1, cmp_BF1_EI0_f1, cmp_HF1_EC0_f1, cmp_DH1_f1, cmp_DH1_EI0_f1, cmp_HF1_EG0_f1, cmp_HF1_f1;
reg cmp_EC0_f1, cmp_EA0_f1, cmp_EG0_f1, cmp_EI0_f1;
reg [23:0] lerp_EB_f1, lerp_ED_f1, lerp_EF_f1, lerp_EH_f1;
reg scaletemp_f2[3][3]; 
reg [23:0] lerp_EB_f2, lerp_ED_f2, lerp_EF_f2, lerp_EH_f2;

// hq
reg [23:0] hq_o, matrix_f1[9], matrix_f2[9];
reg [8:0] hq_op;
reg [1:0] hq_ic;
reg [2:0] row_f[`FILTER_STAGES], col_f[`FILTER_STAGES];
reg [5:0] op_f2, op_mid_f2;
reg [3:0] HQ_A, HQ_B, HQ_C, HQ_D, HQ_E, HQ_F, HQ_G, HQ_H, HQ_I;
reg [7:0] pattern_f1;
reg       middle_f1, middle_f2;
reg [3:0] hq_index_f1[9], hq_index_f2[9];
reg [23:0] hq_data_f2[9], hq_data_f3[9];
reg       center_f2;
reg       cmp_dist_f1;

// copy
reg [23:0] copy_o[`FILTER_STAGES][3][3];

// pass
reg [23:0] pass_o[`FILTER_STAGES];

always @(*) begin

    // hq
    case({row, col})
        // 0,0, 0,1
        6'b000000,6'b000001: begin HQ_A = 0; HQ_B = 1; HQ_C = 2; HQ_D = 3; HQ_F = 5; HQ_G = 6; HQ_H = 7; HQ_I = 8; end
        // 0,2, 1,2
        6'b000010,6'b001010: begin HQ_A = 2; HQ_B = 5; HQ_C = 8; HQ_D = 1; HQ_F = 7; HQ_G = 0; HQ_H = 3; HQ_I = 6; end
        // 1,0  2,0
        6'b001000,6'b010000: begin HQ_A = 6; HQ_B = 3; HQ_C = 0; HQ_D = 7; HQ_F = 1; HQ_G = 8; HQ_H = 5; HQ_I = 2; end
        // 2,1  2,2
        6'b010001,6'b010010: begin HQ_A = 8; HQ_B = 7; HQ_C = 6; HQ_D = 5; HQ_F = 3; HQ_G = 2; HQ_H = 1; HQ_I = 0; end
        default:             begin HQ_A = 0; HQ_B = 1; HQ_C = 2; HQ_D = 3; HQ_F = 5; HQ_G = 6; HQ_H = 7; HQ_I = 8; end
    endcase
    
    HQ_E = 4;

    matrix_f0[`FT_A] = prev_m2;
    matrix_f0[`FT_B] = prev_m1;
    matrix_f0[`FT_C] = prev_in;
    matrix_f0[`FT_D] = curr_m2;
    matrix_f0[`FT_E] = curr_m1;
    matrix_f0[`FT_F] = curr_in;
    matrix_f0[`FT_G] = next_m2;
    matrix_f0[`FT_H] = next_m1;
    matrix_f0[`FT_I] = next_in;
end

// temporary pass through
always @(posedge pclk_act or negedge reset_n)
begin
    if (!reset_n)
        begin
            prev_m2 <= 0;
            prev_m1 <= 0;
            curr_m2 <= 0;
            curr_m1 <= 0;
            next_m2 <= 0;
            next_m1 <= 0;

            data_out <= 0;
            hsync_out <= 0;
            vsync_out <= 0;
            dataenable_out <= 0;
        end
    else
        begin
            // flop the matrix
            if (col == 2) begin
                prev_m2 <= prev_m1;
                prev_m1 <= prev_in;
                curr_m2 <= curr_m1;
                curr_m1 <= curr_in;
                next_m2 <= next_m1;
                next_m1 <= next_in;
            end
            
            matrix_f2 <= matrix_f1;
            matrix_f1 <= matrix_f0;
            
            hsync_f[0] <= hsync_f0;
            vsync_f[0] <= vsync_f0;
            dataenable_f[0] <= dataenable_f0;
            row_f[0] <= row;
            col_f[0] <= col;
            
            // pipeline the other signals
            for (int i = `FILTER_STAGES - 1; i > 0; i--) begin
                hsync_f[i] <= hsync_f[i-1];
                vsync_f[i] <= vsync_f[i-1];
                dataenable_f[i] <= dataenable_f[i-1];
                row_f[i] <= row_f[i-1];
                col_f[i] <= col_f[i-1];
            end

            // <SCALE>
            //========
            // scale f0 - compute conditions
            scalecond_f1 <= cmp(matrix_f0[`FT_B], matrix_f0[`FT_H], 0) && cmp(matrix_f0[`FT_D], matrix_f0[`FT_F], 0);

            cmp_DB1_f1 <= cmp(matrix_f0[`FT_D], matrix_f0[`FT_B], 1);
            cmp_BF1_f1 <= cmp(matrix_f0[`FT_B], matrix_f0[`FT_F], 1);
            cmp_DH1_f1 <= cmp(matrix_f0[`FT_D], matrix_f0[`FT_H], 1);
            cmp_HF1_f1 <= cmp(matrix_f0[`FT_H], matrix_f0[`FT_F], 1);
            cmp_EC0_f1 <= cmp(matrix_f0[`FT_E], matrix_f0[`FT_C], 0);
            cmp_EA0_f1 <= cmp(matrix_f0[`FT_E], matrix_f0[`FT_A], 0);
            cmp_EG0_f1 <= cmp(matrix_f0[`FT_E], matrix_f0[`FT_G], 0);
            cmp_EI0_f1 <= cmp(matrix_f0[`FT_E], matrix_f0[`FT_I], 0);

            cmp_dist_f1 <= cmp_dist(matrix_f0[`FT_D], matrix_f0[`FT_B]) || cmp_dist(matrix_f0[`FT_B], matrix_f0[`FT_F]) || cmp_dist(matrix_f0[`FT_D], matrix_f0[`FT_H]) || cmp_dist(matrix_f0[`FT_H], matrix_f0[`FT_F]) ||
                           cmp_dist(matrix_f0[`FT_B], matrix_f0[`FT_H]) || cmp_dist(matrix_f0[`FT_D], matrix_f0[`FT_F]) ||
                           cmp_dist(matrix_f0[`FT_E], matrix_f0[`FT_C]) || cmp_dist(matrix_f0[`FT_E], matrix_f0[`FT_A]) || cmp_dist(matrix_f0[`FT_E], matrix_f0[`FT_G]) || cmp_dist(matrix_f0[`FT_E], matrix_f0[`FT_I]);
                        
            // f1
            lerp_EB_f2 <= lerp(matrix_f1[`FT_E], matrix_f1[`FT_B], cmp_dist_f1 ? (str >> 1) : str);
            lerp_ED_f2 <= lerp(matrix_f1[`FT_E], matrix_f1[`FT_D], cmp_dist_f1 ? (str >> 1) : str);
            lerp_EF_f2 <= lerp(matrix_f1[`FT_E], matrix_f1[`FT_F], cmp_dist_f1 ? (str >> 1) : str);
            lerp_EH_f2 <= lerp(matrix_f1[`FT_E], matrix_f1[`FT_H], cmp_dist_f1 ? (str >> 1) : str);
            
            scaletemp_f2[0][0] <= (cmp_DB1_f1 && scalecond_f1);
            scaletemp_f2[0][1] <= (((cmp_DB1_f1 && cmp_EC0_f1) || (cmp_BF1_f1 && cmp_EA0_f1)) && scalecond_f1);
            scaletemp_f2[0][2] <= (cmp_BF1_f1 && scalecond_f1);
            scaletemp_f2[1][0] <= (((cmp_DB1_f1 && cmp_EG0_f1) || (cmp_DH1_f1 && cmp_EA0_f1)) && scalecond_f1);
            scaletemp_f2[1][1] <= 1'b1;
            scaletemp_f2[1][2] <= (((cmp_BF1_f1 && cmp_EI0_f1) || (cmp_HF1_f1 && cmp_EC0_f1)) && scalecond_f1);
            scaletemp_f2[2][0] <= (cmp_DH1_f1 && scalecond_f1);
            scaletemp_f2[2][1] <= (((cmp_DH1_f1 && cmp_EI0_f1) || (cmp_HF1_f1 && cmp_EG0_f1)) && scalecond_f1);
            scaletemp_f2[2][2] <= (cmp_HF1_f1 && scalecond_f1);

            // f2
            scale_o[0][0] <= scaletemp_f2[0][0] ? lerp_ED_f2 : pass_o[1];
            scale_o[0][1] <= scaletemp_f2[0][1] ? lerp_EB_f2 : pass_o[1];
            scale_o[0][2] <= scaletemp_f2[0][2] ? lerp_EF_f2 : pass_o[1];
            scale_o[1][0] <= scaletemp_f2[1][0] ? lerp_ED_f2 : pass_o[1];
            scale_o[1][1] <= pass_o[1];
            scale_o[1][2] <= scaletemp_f2[1][2] ? lerp_EF_f2 : pass_o[1];
            scale_o[2][0] <= scaletemp_f2[2][0] ? lerp_ED_f2 : pass_o[1];
            scale_o[2][1] <= scaletemp_f2[2][1] ? lerp_EH_f2 : pass_o[1];
            scale_o[2][2] <= scaletemp_f2[2][2] ? lerp_EF_f2 : pass_o[1];

            // f3
            scale_o_d1 <= scale_o;
             
            // <HQ>
            //========
            // f0
            pattern_f1 <= { pixel_diff(matrix_f0[HQ_E], matrix_f0[HQ_I]),
                            pixel_diff(matrix_f0[HQ_E], matrix_f0[HQ_H]),
                            pixel_diff(matrix_f0[HQ_E], matrix_f0[HQ_G]),
                            pixel_diff(matrix_f0[HQ_E], matrix_f0[HQ_F]),
                            pixel_diff(matrix_f0[HQ_E], matrix_f0[HQ_D]),
                            pixel_diff(matrix_f0[HQ_E], matrix_f0[HQ_C]),
                            pixel_diff(matrix_f0[HQ_E], matrix_f0[HQ_B]),
                            pixel_diff(matrix_f0[HQ_E], matrix_f0[HQ_A]) };
         
            hq_index_f1[`FT_A] <= HQ_A;
            hq_index_f1[`FT_B] <= HQ_B;
            hq_index_f1[`FT_C] <= HQ_C;
            hq_index_f1[`FT_D] <= HQ_D;
            hq_index_f1[`FT_E] <= HQ_E;
            hq_index_f1[`FT_F] <= HQ_F;
            hq_index_f1[`FT_G] <= HQ_G;
            hq_index_f1[`FT_H] <= HQ_H;
            hq_index_f1[`FT_I] <= HQ_I;
         
            middle_f1 <= row == 1 || col == 1;
         
            // f1
            op_f2 <= middle_f1 ? hqTable3x[pattern_f1] : hqTable[pattern_f1];
            
            hq_data_f2[`FT_A] <= matrix_f1[hq_index_f1[`FT_A]];
            hq_data_f2[`FT_B] <= matrix_f1[hq_index_f1[`FT_B]];
            hq_data_f2[`FT_C] <= matrix_f1[hq_index_f1[`FT_C]];
            //hq_data_f2[`FT_D] <= matrix_f1[middle_f1 ? hq_index_f1[`FT_B] : hq_index_f1[`FT_D]];
            hq_data_f2[`FT_D] <= matrix_f1[hq_index_f1[`FT_D]];
            hq_data_f2[`FT_E] <= matrix_f1[hq_index_f1[`FT_E]];
            hq_data_f2[`FT_F] <= matrix_f1[hq_index_f1[`FT_F]];
            hq_data_f2[`FT_G] <= matrix_f1[hq_index_f1[`FT_G]];
            //hq_data_f2[`FT_H] <= matrix_f1[middle_f1 ? hq_index_f1[`FT_B] : hq_index_f1[`FT_H]];
            hq_data_f2[`FT_H] <= matrix_f1[hq_index_f1[`FT_H]];
            hq_data_f2[`FT_I] <= matrix_f1[hq_index_f1[`FT_I]];
            
            middle_f2 <= middle_f1;
            center_f2 <= (row_f[0] == 1 && col_f[0] == 1);
            
            // f2
            {hq_op, hq_ic} <= BlendCtrl(op_f2, center_f2, hq_data_f2[`FT_E], hq_data_f2[`FT_A], hq_data_f2[`FT_B], hq_data_f2[`FT_D], hq_data_f2[`FT_F], hq_data_f2[`FT_H]);
            hq_data_f3[`FT_A] <= hq_data_f2[`FT_A];
            hq_data_f3[`FT_B] <= hq_data_f2[`FT_B];
            hq_data_f3[`FT_C] <= hq_data_f2[`FT_C];
            // fix middle pixel colors by swapping D with B.  We only need to interpolate E w/ B for the middle.
            hq_data_f3[`FT_D] <= middle_f2 ? hq_data_f2[`FT_B] : hq_data_f2[`FT_D];
            hq_data_f3[`FT_E] <= hq_data_f2[`FT_E];
            hq_data_f3[`FT_F] <= hq_data_f2[`FT_F];
            hq_data_f3[`FT_G] <= hq_data_f2[`FT_G];
            hq_data_f3[`FT_H] <= hq_data_f2[`FT_H];
            hq_data_f3[`FT_I] <= hq_data_f2[`FT_I];
 
            // f3
            hq_o <= FinalBlend(hq_op, hq_ic, hq_data_f3[`FT_E], hq_data_f3[`FT_A], hq_data_f3[`FT_B], hq_data_f3[`FT_D]);
 

            copy_o[0][0][0] <= pixel_diff(matrix_f0[`FT_E], matrix_f0[`FT_A]) ? 24'HFF0000 : 24'H00FF00;
            copy_o[0][0][1] <= pixel_diff(matrix_f0[`FT_E], matrix_f0[`FT_B]) ? 24'HFF0000 : 24'H00FF00;
            copy_o[0][0][2] <= pixel_diff(matrix_f0[`FT_E], matrix_f0[`FT_C]) ? 24'HFF0000 : 24'H00FF00;
            copy_o[0][1][0] <= pixel_diff(matrix_f0[`FT_E], matrix_f0[`FT_D]) ? 24'HFF0000 : 24'H00FF00;
            copy_o[0][1][1] <= pixel_diff(matrix_f0[`FT_E], matrix_f0[`FT_E]) ? 24'HFF0000 : 24'H00FF00;
            copy_o[0][1][2] <= pixel_diff(matrix_f0[`FT_E], matrix_f0[`FT_F]) ? 24'HFF0000 : 24'H00FF00;
            copy_o[0][2][0] <= pixel_diff(matrix_f0[`FT_E], matrix_f0[`FT_G]) ? 24'HFF0000 : 24'H00FF00;
            copy_o[0][2][1] <= pixel_diff(matrix_f0[`FT_E], matrix_f0[`FT_H]) ? 24'HFF0000 : 24'H00FF00;
            copy_o[0][2][2] <= pixel_diff(matrix_f0[`FT_E], matrix_f0[`FT_I]) ? 24'HFF0000 : 24'H00FF00;
            
            for (int i = `FILTER_STAGES - 1; i > 0; i--) begin
                copy_o[i] <= copy_o[i-1];
            end
            
            // <PASS>
            //======
            pass_o[0] <= matrix_f0[`FT_E];
            for (int i = `FILTER_STAGES - 1; i > 0; i--) begin
                pass_o[i] <= pass_o[i-1];
            end
            
            // OUTPUT STAGE
            // pick output
            case (mode)
                1: data_out <= scale_o_d1[row_f[`FILTER_STAGES-1]][col_f[`FILTER_STAGES-1]];
                2: data_out <= hq_o; // hq_o[row_f[`FILTER_STAGES-1]][col_f[`FILTER_STAGES-1]];
                3: data_out <= copy_o[`FILTER_STAGES-1][row_f[`FILTER_STAGES-1]][col_f[`FILTER_STAGES-1]];
                default: data_out <= pass_o[`FILTER_STAGES-1];
            endcase

            hsync_out <= hsync_f[`FILTER_STAGES-1];
            vsync_out <= vsync_f[`FILTER_STAGES-1];
            dataenable_out <= dataenable_f[`FILTER_STAGES-1];
            col_out <= col_f[`FILTER_STAGES-1];
            row_out <= row_f[`FILTER_STAGES-1];
        end
end

endmodule
