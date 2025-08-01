import {
  __commonJS,
  __export,
  __objRest,
  __spreadProps,
  __spreadValues,
  __toESM
} from "./chunk-N6ESDQJH.js";

// node_modules/fast-diff/diff.js
var require_diff = __commonJS({
  "node_modules/fast-diff/diff.js"(exports2, module2) {
    var DIFF_DELETE = -1;
    var DIFF_INSERT = 1;
    var DIFF_EQUAL = 0;
    function diff_main(text1, text2, cursor_pos, cleanup, _fix_unicode) {
      if (text1 === text2) {
        if (text1) {
          return [[DIFF_EQUAL, text1]];
        }
        return [];
      }
      if (cursor_pos != null) {
        var editdiff = find_cursor_edit_diff(text1, text2, cursor_pos);
        if (editdiff) {
          return editdiff;
        }
      }
      var commonlength = diff_commonPrefix(text1, text2);
      var commonprefix = text1.substring(0, commonlength);
      text1 = text1.substring(commonlength);
      text2 = text2.substring(commonlength);
      commonlength = diff_commonSuffix(text1, text2);
      var commonsuffix = text1.substring(text1.length - commonlength);
      text1 = text1.substring(0, text1.length - commonlength);
      text2 = text2.substring(0, text2.length - commonlength);
      var diffs = diff_compute_(text1, text2);
      if (commonprefix) {
        diffs.unshift([DIFF_EQUAL, commonprefix]);
      }
      if (commonsuffix) {
        diffs.push([DIFF_EQUAL, commonsuffix]);
      }
      diff_cleanupMerge(diffs, _fix_unicode);
      if (cleanup) {
        diff_cleanupSemantic(diffs);
      }
      return diffs;
    }
    function diff_compute_(text1, text2) {
      var diffs;
      if (!text1) {
        return [[DIFF_INSERT, text2]];
      }
      if (!text2) {
        return [[DIFF_DELETE, text1]];
      }
      var longtext = text1.length > text2.length ? text1 : text2;
      var shorttext = text1.length > text2.length ? text2 : text1;
      var i = longtext.indexOf(shorttext);
      if (i !== -1) {
        diffs = [[DIFF_INSERT, longtext.substring(0, i)], [DIFF_EQUAL, shorttext], [DIFF_INSERT, longtext.substring(i + shorttext.length)]];
        if (text1.length > text2.length) {
          diffs[0][0] = diffs[2][0] = DIFF_DELETE;
        }
        return diffs;
      }
      if (shorttext.length === 1) {
        return [[DIFF_DELETE, text1], [DIFF_INSERT, text2]];
      }
      var hm = diff_halfMatch_(text1, text2);
      if (hm) {
        var text1_a = hm[0];
        var text1_b = hm[1];
        var text2_a = hm[2];
        var text2_b = hm[3];
        var mid_common = hm[4];
        var diffs_a = diff_main(text1_a, text2_a);
        var diffs_b = diff_main(text1_b, text2_b);
        return diffs_a.concat([[DIFF_EQUAL, mid_common]], diffs_b);
      }
      return diff_bisect_(text1, text2);
    }
    function diff_bisect_(text1, text2) {
      var text1_length = text1.length;
      var text2_length = text2.length;
      var max_d = Math.ceil((text1_length + text2_length) / 2);
      var v_offset = max_d;
      var v_length = 2 * max_d;
      var v1 = new Array(v_length);
      var v2 = new Array(v_length);
      for (var x = 0; x < v_length; x++) {
        v1[x] = -1;
        v2[x] = -1;
      }
      v1[v_offset + 1] = 0;
      v2[v_offset + 1] = 0;
      var delta = text1_length - text2_length;
      var front = delta % 2 !== 0;
      var k1start = 0;
      var k1end = 0;
      var k2start = 0;
      var k2end = 0;
      for (var d = 0; d < max_d; d++) {
        for (var k1 = -d + k1start; k1 <= d - k1end; k1 += 2) {
          var k1_offset = v_offset + k1;
          var x1;
          if (k1 === -d || k1 !== d && v1[k1_offset - 1] < v1[k1_offset + 1]) {
            x1 = v1[k1_offset + 1];
          } else {
            x1 = v1[k1_offset - 1] + 1;
          }
          var y1 = x1 - k1;
          while (x1 < text1_length && y1 < text2_length && text1.charAt(x1) === text2.charAt(y1)) {
            x1++;
            y1++;
          }
          v1[k1_offset] = x1;
          if (x1 > text1_length) {
            k1end += 2;
          } else if (y1 > text2_length) {
            k1start += 2;
          } else if (front) {
            var k2_offset = v_offset + delta - k1;
            if (k2_offset >= 0 && k2_offset < v_length && v2[k2_offset] !== -1) {
              var x2 = text1_length - v2[k2_offset];
              if (x1 >= x2) {
                return diff_bisectSplit_(text1, text2, x1, y1);
              }
            }
          }
        }
        for (var k2 = -d + k2start; k2 <= d - k2end; k2 += 2) {
          var k2_offset = v_offset + k2;
          var x2;
          if (k2 === -d || k2 !== d && v2[k2_offset - 1] < v2[k2_offset + 1]) {
            x2 = v2[k2_offset + 1];
          } else {
            x2 = v2[k2_offset - 1] + 1;
          }
          var y2 = x2 - k2;
          while (x2 < text1_length && y2 < text2_length && text1.charAt(text1_length - x2 - 1) === text2.charAt(text2_length - y2 - 1)) {
            x2++;
            y2++;
          }
          v2[k2_offset] = x2;
          if (x2 > text1_length) {
            k2end += 2;
          } else if (y2 > text2_length) {
            k2start += 2;
          } else if (!front) {
            var k1_offset = v_offset + delta - k2;
            if (k1_offset >= 0 && k1_offset < v_length && v1[k1_offset] !== -1) {
              var x1 = v1[k1_offset];
              var y1 = v_offset + x1 - k1_offset;
              x2 = text1_length - x2;
              if (x1 >= x2) {
                return diff_bisectSplit_(text1, text2, x1, y1);
              }
            }
          }
        }
      }
      return [[DIFF_DELETE, text1], [DIFF_INSERT, text2]];
    }
    function diff_bisectSplit_(text1, text2, x, y) {
      var text1a = text1.substring(0, x);
      var text2a = text2.substring(0, y);
      var text1b = text1.substring(x);
      var text2b = text2.substring(y);
      var diffs = diff_main(text1a, text2a);
      var diffsb = diff_main(text1b, text2b);
      return diffs.concat(diffsb);
    }
    function diff_commonPrefix(text1, text2) {
      if (!text1 || !text2 || text1.charAt(0) !== text2.charAt(0)) {
        return 0;
      }
      var pointermin = 0;
      var pointermax = Math.min(text1.length, text2.length);
      var pointermid = pointermax;
      var pointerstart = 0;
      while (pointermin < pointermid) {
        if (text1.substring(pointerstart, pointermid) == text2.substring(pointerstart, pointermid)) {
          pointermin = pointermid;
          pointerstart = pointermin;
        } else {
          pointermax = pointermid;
        }
        pointermid = Math.floor((pointermax - pointermin) / 2 + pointermin);
      }
      if (is_surrogate_pair_start(text1.charCodeAt(pointermid - 1))) {
        pointermid--;
      }
      return pointermid;
    }
    function diff_commonOverlap_(text1, text2) {
      var text1_length = text1.length;
      var text2_length = text2.length;
      if (text1_length == 0 || text2_length == 0) {
        return 0;
      }
      if (text1_length > text2_length) {
        text1 = text1.substring(text1_length - text2_length);
      } else if (text1_length < text2_length) {
        text2 = text2.substring(0, text1_length);
      }
      var text_length = Math.min(text1_length, text2_length);
      if (text1 == text2) {
        return text_length;
      }
      var best = 0;
      var length = 1;
      while (true) {
        var pattern = text1.substring(text_length - length);
        var found = text2.indexOf(pattern);
        if (found == -1) {
          return best;
        }
        length += found;
        if (found == 0 || text1.substring(text_length - length) == text2.substring(0, length)) {
          best = length;
          length++;
        }
      }
    }
    function diff_commonSuffix(text1, text2) {
      if (!text1 || !text2 || text1.slice(-1) !== text2.slice(-1)) {
        return 0;
      }
      var pointermin = 0;
      var pointermax = Math.min(text1.length, text2.length);
      var pointermid = pointermax;
      var pointerend = 0;
      while (pointermin < pointermid) {
        if (text1.substring(text1.length - pointermid, text1.length - pointerend) == text2.substring(text2.length - pointermid, text2.length - pointerend)) {
          pointermin = pointermid;
          pointerend = pointermin;
        } else {
          pointermax = pointermid;
        }
        pointermid = Math.floor((pointermax - pointermin) / 2 + pointermin);
      }
      if (is_surrogate_pair_end(text1.charCodeAt(text1.length - pointermid))) {
        pointermid--;
      }
      return pointermid;
    }
    function diff_halfMatch_(text1, text2) {
      var longtext = text1.length > text2.length ? text1 : text2;
      var shorttext = text1.length > text2.length ? text2 : text1;
      if (longtext.length < 4 || shorttext.length * 2 < longtext.length) {
        return null;
      }
      function diff_halfMatchI_(longtext2, shorttext2, i) {
        var seed = longtext2.substring(i, i + Math.floor(longtext2.length / 4));
        var j = -1;
        var best_common = "";
        var best_longtext_a, best_longtext_b, best_shorttext_a, best_shorttext_b;
        while ((j = shorttext2.indexOf(seed, j + 1)) !== -1) {
          var prefixLength = diff_commonPrefix(longtext2.substring(i), shorttext2.substring(j));
          var suffixLength = diff_commonSuffix(longtext2.substring(0, i), shorttext2.substring(0, j));
          if (best_common.length < suffixLength + prefixLength) {
            best_common = shorttext2.substring(j - suffixLength, j) + shorttext2.substring(j, j + prefixLength);
            best_longtext_a = longtext2.substring(0, i - suffixLength);
            best_longtext_b = longtext2.substring(i + prefixLength);
            best_shorttext_a = shorttext2.substring(0, j - suffixLength);
            best_shorttext_b = shorttext2.substring(j + prefixLength);
          }
        }
        if (best_common.length * 2 >= longtext2.length) {
          return [best_longtext_a, best_longtext_b, best_shorttext_a, best_shorttext_b, best_common];
        } else {
          return null;
        }
      }
      var hm1 = diff_halfMatchI_(longtext, shorttext, Math.ceil(longtext.length / 4));
      var hm2 = diff_halfMatchI_(longtext, shorttext, Math.ceil(longtext.length / 2));
      var hm;
      if (!hm1 && !hm2) {
        return null;
      } else if (!hm2) {
        hm = hm1;
      } else if (!hm1) {
        hm = hm2;
      } else {
        hm = hm1[4].length > hm2[4].length ? hm1 : hm2;
      }
      var text1_a, text1_b, text2_a, text2_b;
      if (text1.length > text2.length) {
        text1_a = hm[0];
        text1_b = hm[1];
        text2_a = hm[2];
        text2_b = hm[3];
      } else {
        text2_a = hm[0];
        text2_b = hm[1];
        text1_a = hm[2];
        text1_b = hm[3];
      }
      var mid_common = hm[4];
      return [text1_a, text1_b, text2_a, text2_b, mid_common];
    }
    function diff_cleanupSemantic(diffs) {
      var changes = false;
      var equalities = [];
      var equalitiesLength = 0;
      var lastequality = null;
      var pointer = 0;
      var length_insertions1 = 0;
      var length_deletions1 = 0;
      var length_insertions2 = 0;
      var length_deletions2 = 0;
      while (pointer < diffs.length) {
        if (diffs[pointer][0] == DIFF_EQUAL) {
          equalities[equalitiesLength++] = pointer;
          length_insertions1 = length_insertions2;
          length_deletions1 = length_deletions2;
          length_insertions2 = 0;
          length_deletions2 = 0;
          lastequality = diffs[pointer][1];
        } else {
          if (diffs[pointer][0] == DIFF_INSERT) {
            length_insertions2 += diffs[pointer][1].length;
          } else {
            length_deletions2 += diffs[pointer][1].length;
          }
          if (lastequality && lastequality.length <= Math.max(length_insertions1, length_deletions1) && lastequality.length <= Math.max(length_insertions2, length_deletions2)) {
            diffs.splice(equalities[equalitiesLength - 1], 0, [DIFF_DELETE, lastequality]);
            diffs[equalities[equalitiesLength - 1] + 1][0] = DIFF_INSERT;
            equalitiesLength--;
            equalitiesLength--;
            pointer = equalitiesLength > 0 ? equalities[equalitiesLength - 1] : -1;
            length_insertions1 = 0;
            length_deletions1 = 0;
            length_insertions2 = 0;
            length_deletions2 = 0;
            lastequality = null;
            changes = true;
          }
        }
        pointer++;
      }
      if (changes) {
        diff_cleanupMerge(diffs);
      }
      diff_cleanupSemanticLossless(diffs);
      pointer = 1;
      while (pointer < diffs.length) {
        if (diffs[pointer - 1][0] == DIFF_DELETE && diffs[pointer][0] == DIFF_INSERT) {
          var deletion = diffs[pointer - 1][1];
          var insertion = diffs[pointer][1];
          var overlap_length1 = diff_commonOverlap_(deletion, insertion);
          var overlap_length2 = diff_commonOverlap_(insertion, deletion);
          if (overlap_length1 >= overlap_length2) {
            if (overlap_length1 >= deletion.length / 2 || overlap_length1 >= insertion.length / 2) {
              diffs.splice(pointer, 0, [DIFF_EQUAL, insertion.substring(0, overlap_length1)]);
              diffs[pointer - 1][1] = deletion.substring(0, deletion.length - overlap_length1);
              diffs[pointer + 1][1] = insertion.substring(overlap_length1);
              pointer++;
            }
          } else {
            if (overlap_length2 >= deletion.length / 2 || overlap_length2 >= insertion.length / 2) {
              diffs.splice(pointer, 0, [DIFF_EQUAL, deletion.substring(0, overlap_length2)]);
              diffs[pointer - 1][0] = DIFF_INSERT;
              diffs[pointer - 1][1] = insertion.substring(0, insertion.length - overlap_length2);
              diffs[pointer + 1][0] = DIFF_DELETE;
              diffs[pointer + 1][1] = deletion.substring(overlap_length2);
              pointer++;
            }
          }
          pointer++;
        }
        pointer++;
      }
    }
    var nonAlphaNumericRegex_ = /[^a-zA-Z0-9]/;
    var whitespaceRegex_ = /\s/;
    var linebreakRegex_ = /[\r\n]/;
    var blanklineEndRegex_ = /\n\r?\n$/;
    var blanklineStartRegex_ = /^\r?\n\r?\n/;
    function diff_cleanupSemanticLossless(diffs) {
      function diff_cleanupSemanticScore_(one, two) {
        if (!one || !two) {
          return 6;
        }
        var char1 = one.charAt(one.length - 1);
        var char2 = two.charAt(0);
        var nonAlphaNumeric1 = char1.match(nonAlphaNumericRegex_);
        var nonAlphaNumeric2 = char2.match(nonAlphaNumericRegex_);
        var whitespace1 = nonAlphaNumeric1 && char1.match(whitespaceRegex_);
        var whitespace2 = nonAlphaNumeric2 && char2.match(whitespaceRegex_);
        var lineBreak1 = whitespace1 && char1.match(linebreakRegex_);
        var lineBreak2 = whitespace2 && char2.match(linebreakRegex_);
        var blankLine1 = lineBreak1 && one.match(blanklineEndRegex_);
        var blankLine2 = lineBreak2 && two.match(blanklineStartRegex_);
        if (blankLine1 || blankLine2) {
          return 5;
        } else if (lineBreak1 || lineBreak2) {
          return 4;
        } else if (nonAlphaNumeric1 && !whitespace1 && whitespace2) {
          return 3;
        } else if (whitespace1 || whitespace2) {
          return 2;
        } else if (nonAlphaNumeric1 || nonAlphaNumeric2) {
          return 1;
        }
        return 0;
      }
      var pointer = 1;
      while (pointer < diffs.length - 1) {
        if (diffs[pointer - 1][0] == DIFF_EQUAL && diffs[pointer + 1][0] == DIFF_EQUAL) {
          var equality1 = diffs[pointer - 1][1];
          var edit = diffs[pointer][1];
          var equality2 = diffs[pointer + 1][1];
          var commonOffset = diff_commonSuffix(equality1, edit);
          if (commonOffset) {
            var commonString = edit.substring(edit.length - commonOffset);
            equality1 = equality1.substring(0, equality1.length - commonOffset);
            edit = commonString + edit.substring(0, edit.length - commonOffset);
            equality2 = commonString + equality2;
          }
          var bestEquality1 = equality1;
          var bestEdit = edit;
          var bestEquality2 = equality2;
          var bestScore = diff_cleanupSemanticScore_(equality1, edit) + diff_cleanupSemanticScore_(edit, equality2);
          while (edit.charAt(0) === equality2.charAt(0)) {
            equality1 += edit.charAt(0);
            edit = edit.substring(1) + equality2.charAt(0);
            equality2 = equality2.substring(1);
            var score = diff_cleanupSemanticScore_(equality1, edit) + diff_cleanupSemanticScore_(edit, equality2);
            if (score >= bestScore) {
              bestScore = score;
              bestEquality1 = equality1;
              bestEdit = edit;
              bestEquality2 = equality2;
            }
          }
          if (diffs[pointer - 1][1] != bestEquality1) {
            if (bestEquality1) {
              diffs[pointer - 1][1] = bestEquality1;
            } else {
              diffs.splice(pointer - 1, 1);
              pointer--;
            }
            diffs[pointer][1] = bestEdit;
            if (bestEquality2) {
              diffs[pointer + 1][1] = bestEquality2;
            } else {
              diffs.splice(pointer + 1, 1);
              pointer--;
            }
          }
        }
        pointer++;
      }
    }
    function diff_cleanupMerge(diffs, fix_unicode) {
      diffs.push([DIFF_EQUAL, ""]);
      var pointer = 0;
      var count_delete = 0;
      var count_insert = 0;
      var text_delete = "";
      var text_insert = "";
      var commonlength;
      while (pointer < diffs.length) {
        if (pointer < diffs.length - 1 && !diffs[pointer][1]) {
          diffs.splice(pointer, 1);
          continue;
        }
        switch (diffs[pointer][0]) {
          case DIFF_INSERT:
            count_insert++;
            text_insert += diffs[pointer][1];
            pointer++;
            break;
          case DIFF_DELETE:
            count_delete++;
            text_delete += diffs[pointer][1];
            pointer++;
            break;
          case DIFF_EQUAL:
            var previous_equality = pointer - count_insert - count_delete - 1;
            if (fix_unicode) {
              if (previous_equality >= 0 && ends_with_pair_start(diffs[previous_equality][1])) {
                var stray = diffs[previous_equality][1].slice(-1);
                diffs[previous_equality][1] = diffs[previous_equality][1].slice(0, -1);
                text_delete = stray + text_delete;
                text_insert = stray + text_insert;
                if (!diffs[previous_equality][1]) {
                  diffs.splice(previous_equality, 1);
                  pointer--;
                  var k = previous_equality - 1;
                  if (diffs[k] && diffs[k][0] === DIFF_INSERT) {
                    count_insert++;
                    text_insert = diffs[k][1] + text_insert;
                    k--;
                  }
                  if (diffs[k] && diffs[k][0] === DIFF_DELETE) {
                    count_delete++;
                    text_delete = diffs[k][1] + text_delete;
                    k--;
                  }
                  previous_equality = k;
                }
              }
              if (starts_with_pair_end(diffs[pointer][1])) {
                var stray = diffs[pointer][1].charAt(0);
                diffs[pointer][1] = diffs[pointer][1].slice(1);
                text_delete += stray;
                text_insert += stray;
              }
            }
            if (pointer < diffs.length - 1 && !diffs[pointer][1]) {
              diffs.splice(pointer, 1);
              break;
            }
            if (text_delete.length > 0 || text_insert.length > 0) {
              if (text_delete.length > 0 && text_insert.length > 0) {
                commonlength = diff_commonPrefix(text_insert, text_delete);
                if (commonlength !== 0) {
                  if (previous_equality >= 0) {
                    diffs[previous_equality][1] += text_insert.substring(0, commonlength);
                  } else {
                    diffs.splice(0, 0, [DIFF_EQUAL, text_insert.substring(0, commonlength)]);
                    pointer++;
                  }
                  text_insert = text_insert.substring(commonlength);
                  text_delete = text_delete.substring(commonlength);
                }
                commonlength = diff_commonSuffix(text_insert, text_delete);
                if (commonlength !== 0) {
                  diffs[pointer][1] = text_insert.substring(text_insert.length - commonlength) + diffs[pointer][1];
                  text_insert = text_insert.substring(0, text_insert.length - commonlength);
                  text_delete = text_delete.substring(0, text_delete.length - commonlength);
                }
              }
              var n = count_insert + count_delete;
              if (text_delete.length === 0 && text_insert.length === 0) {
                diffs.splice(pointer - n, n);
                pointer = pointer - n;
              } else if (text_delete.length === 0) {
                diffs.splice(pointer - n, n, [DIFF_INSERT, text_insert]);
                pointer = pointer - n + 1;
              } else if (text_insert.length === 0) {
                diffs.splice(pointer - n, n, [DIFF_DELETE, text_delete]);
                pointer = pointer - n + 1;
              } else {
                diffs.splice(pointer - n, n, [DIFF_DELETE, text_delete], [DIFF_INSERT, text_insert]);
                pointer = pointer - n + 2;
              }
            }
            if (pointer !== 0 && diffs[pointer - 1][0] === DIFF_EQUAL) {
              diffs[pointer - 1][1] += diffs[pointer][1];
              diffs.splice(pointer, 1);
            } else {
              pointer++;
            }
            count_insert = 0;
            count_delete = 0;
            text_delete = "";
            text_insert = "";
            break;
        }
      }
      if (diffs[diffs.length - 1][1] === "") {
        diffs.pop();
      }
      var changes = false;
      pointer = 1;
      while (pointer < diffs.length - 1) {
        if (diffs[pointer - 1][0] === DIFF_EQUAL && diffs[pointer + 1][0] === DIFF_EQUAL) {
          if (diffs[pointer][1].substring(diffs[pointer][1].length - diffs[pointer - 1][1].length) === diffs[pointer - 1][1]) {
            diffs[pointer][1] = diffs[pointer - 1][1] + diffs[pointer][1].substring(0, diffs[pointer][1].length - diffs[pointer - 1][1].length);
            diffs[pointer + 1][1] = diffs[pointer - 1][1] + diffs[pointer + 1][1];
            diffs.splice(pointer - 1, 1);
            changes = true;
          } else if (diffs[pointer][1].substring(0, diffs[pointer + 1][1].length) == diffs[pointer + 1][1]) {
            diffs[pointer - 1][1] += diffs[pointer + 1][1];
            diffs[pointer][1] = diffs[pointer][1].substring(diffs[pointer + 1][1].length) + diffs[pointer + 1][1];
            diffs.splice(pointer + 1, 1);
            changes = true;
          }
        }
        pointer++;
      }
      if (changes) {
        diff_cleanupMerge(diffs, fix_unicode);
      }
    }
    function is_surrogate_pair_start(charCode) {
      return charCode >= 55296 && charCode <= 56319;
    }
    function is_surrogate_pair_end(charCode) {
      return charCode >= 56320 && charCode <= 57343;
    }
    function starts_with_pair_end(str) {
      return is_surrogate_pair_end(str.charCodeAt(0));
    }
    function ends_with_pair_start(str) {
      return is_surrogate_pair_start(str.charCodeAt(str.length - 1));
    }
    function remove_empty_tuples(tuples) {
      var ret = [];
      for (var i = 0; i < tuples.length; i++) {
        if (tuples[i][1].length > 0) {
          ret.push(tuples[i]);
        }
      }
      return ret;
    }
    function make_edit_splice(before2, oldMiddle, newMiddle, after2) {
      if (ends_with_pair_start(before2) || starts_with_pair_end(after2)) {
        return null;
      }
      return remove_empty_tuples([[DIFF_EQUAL, before2], [DIFF_DELETE, oldMiddle], [DIFF_INSERT, newMiddle], [DIFF_EQUAL, after2]]);
    }
    function find_cursor_edit_diff(oldText, newText, cursor_pos) {
      var oldRange = typeof cursor_pos === "number" ? {
        index: cursor_pos,
        length: 0
      } : cursor_pos.oldRange;
      var newRange = typeof cursor_pos === "number" ? null : cursor_pos.newRange;
      var oldLength = oldText.length;
      var newLength = newText.length;
      if (oldRange.length === 0 && (newRange === null || newRange.length === 0)) {
        var oldCursor = oldRange.index;
        var oldBefore = oldText.slice(0, oldCursor);
        var oldAfter = oldText.slice(oldCursor);
        var maybeNewCursor = newRange ? newRange.index : null;
        editBefore: {
          var newCursor = oldCursor + newLength - oldLength;
          if (maybeNewCursor !== null && maybeNewCursor !== newCursor) {
            break editBefore;
          }
          if (newCursor < 0 || newCursor > newLength) {
            break editBefore;
          }
          var newBefore = newText.slice(0, newCursor);
          var newAfter = newText.slice(newCursor);
          if (newAfter !== oldAfter) {
            break editBefore;
          }
          var prefixLength = Math.min(oldCursor, newCursor);
          var oldPrefix = oldBefore.slice(0, prefixLength);
          var newPrefix = newBefore.slice(0, prefixLength);
          if (oldPrefix !== newPrefix) {
            break editBefore;
          }
          var oldMiddle = oldBefore.slice(prefixLength);
          var newMiddle = newBefore.slice(prefixLength);
          return make_edit_splice(oldPrefix, oldMiddle, newMiddle, oldAfter);
        }
        editAfter: {
          if (maybeNewCursor !== null && maybeNewCursor !== oldCursor) {
            break editAfter;
          }
          var cursor = oldCursor;
          var newBefore = newText.slice(0, cursor);
          var newAfter = newText.slice(cursor);
          if (newBefore !== oldBefore) {
            break editAfter;
          }
          var suffixLength = Math.min(oldLength - cursor, newLength - cursor);
          var oldSuffix = oldAfter.slice(oldAfter.length - suffixLength);
          var newSuffix = newAfter.slice(newAfter.length - suffixLength);
          if (oldSuffix !== newSuffix) {
            break editAfter;
          }
          var oldMiddle = oldAfter.slice(0, oldAfter.length - suffixLength);
          var newMiddle = newAfter.slice(0, newAfter.length - suffixLength);
          return make_edit_splice(oldBefore, oldMiddle, newMiddle, oldSuffix);
        }
      }
      if (oldRange.length > 0 && newRange && newRange.length === 0) {
        replaceRange: {
          var oldPrefix = oldText.slice(0, oldRange.index);
          var oldSuffix = oldText.slice(oldRange.index + oldRange.length);
          var prefixLength = oldPrefix.length;
          var suffixLength = oldSuffix.length;
          if (newLength < prefixLength + suffixLength) {
            break replaceRange;
          }
          var newPrefix = newText.slice(0, prefixLength);
          var newSuffix = newText.slice(newLength - suffixLength);
          if (oldPrefix !== newPrefix || oldSuffix !== newSuffix) {
            break replaceRange;
          }
          var oldMiddle = oldText.slice(prefixLength, oldLength - suffixLength);
          var newMiddle = newText.slice(prefixLength, newLength - suffixLength);
          return make_edit_splice(oldPrefix, oldMiddle, newMiddle, oldSuffix);
        }
      }
      return null;
    }
    function diff(text1, text2, cursor_pos, cleanup) {
      return diff_main(text1, text2, cursor_pos, cleanup, true);
    }
    diff.INSERT = DIFF_INSERT;
    diff.DELETE = DIFF_DELETE;
    diff.EQUAL = DIFF_EQUAL;
    module2.exports = diff;
  }
});

// node_modules/lodash.clonedeep/index.js
var require_lodash = __commonJS({
  "node_modules/lodash.clonedeep/index.js"(exports2, module2) {
    var LARGE_ARRAY_SIZE4 = 200;
    var HASH_UNDEFINED4 = "__lodash_hash_undefined__";
    var MAX_SAFE_INTEGER7 = 9007199254740991;
    var argsTag5 = "[object Arguments]";
    var arrayTag4 = "[object Array]";
    var boolTag6 = "[object Boolean]";
    var dateTag6 = "[object Date]";
    var errorTag5 = "[object Error]";
    var funcTag4 = "[object Function]";
    var genTag3 = "[object GeneratorFunction]";
    var mapTag11 = "[object Map]";
    var numberTag6 = "[object Number]";
    var objectTag6 = "[object Object]";
    var promiseTag2 = "[object Promise]";
    var regexpTag6 = "[object RegExp]";
    var setTag11 = "[object Set]";
    var stringTag6 = "[object String]";
    var symbolTag5 = "[object Symbol]";
    var weakMapTag5 = "[object WeakMap]";
    var arrayBufferTag6 = "[object ArrayBuffer]";
    var dataViewTag6 = "[object DataView]";
    var float32Tag4 = "[object Float32Array]";
    var float64Tag4 = "[object Float64Array]";
    var int8Tag4 = "[object Int8Array]";
    var int16Tag4 = "[object Int16Array]";
    var int32Tag4 = "[object Int32Array]";
    var uint8Tag4 = "[object Uint8Array]";
    var uint8ClampedTag4 = "[object Uint8ClampedArray]";
    var uint16Tag4 = "[object Uint16Array]";
    var uint32Tag4 = "[object Uint32Array]";
    var reRegExpChar3 = /[\\^$.*+?()[\]{}|]/g;
    var reFlags3 = /\w*$/;
    var reIsHostCtor2 = /^\[object .+?Constructor\]$/;
    var reIsUint2 = /^(?:0|[1-9]\d*)$/;
    var cloneableTags2 = {};
    cloneableTags2[argsTag5] = cloneableTags2[arrayTag4] = cloneableTags2[arrayBufferTag6] = cloneableTags2[dataViewTag6] = cloneableTags2[boolTag6] = cloneableTags2[dateTag6] = cloneableTags2[float32Tag4] = cloneableTags2[float64Tag4] = cloneableTags2[int8Tag4] = cloneableTags2[int16Tag4] = cloneableTags2[int32Tag4] = cloneableTags2[mapTag11] = cloneableTags2[numberTag6] = cloneableTags2[objectTag6] = cloneableTags2[regexpTag6] = cloneableTags2[setTag11] = cloneableTags2[stringTag6] = cloneableTags2[symbolTag5] = cloneableTags2[uint8Tag4] = cloneableTags2[uint8ClampedTag4] = cloneableTags2[uint16Tag4] = cloneableTags2[uint32Tag4] = true;
    cloneableTags2[errorTag5] = cloneableTags2[funcTag4] = cloneableTags2[weakMapTag5] = false;
    var freeGlobal2 = typeof global == "object" && global && global.Object === Object && global;
    var freeSelf2 = typeof self == "object" && self && self.Object === Object && self;
    var root2 = freeGlobal2 || freeSelf2 || Function("return this")();
    var freeExports4 = typeof exports2 == "object" && exports2 && !exports2.nodeType && exports2;
    var freeModule4 = freeExports4 && typeof module2 == "object" && module2 && !module2.nodeType && module2;
    var moduleExports4 = freeModule4 && freeModule4.exports === freeExports4;
    function addMapEntry(map2, pair) {
      map2.set(pair[0], pair[1]);
      return map2;
    }
    function addSetEntry(set2, value) {
      set2.add(value);
      return set2;
    }
    function arrayEach2(array, iteratee2) {
      var index = -1, length = array ? array.length : 0;
      while (++index < length) {
        if (iteratee2(array[index], index, array) === false) {
          break;
        }
      }
      return array;
    }
    function arrayPush2(array, values2) {
      var index = -1, length = values2.length, offset = array.length;
      while (++index < length) {
        array[offset + index] = values2[index];
      }
      return array;
    }
    function arrayReduce2(array, iteratee2, accumulator, initAccum) {
      var index = -1, length = array ? array.length : 0;
      if (initAccum && length) {
        accumulator = array[++index];
      }
      while (++index < length) {
        accumulator = iteratee2(accumulator, array[index], index, array);
      }
      return accumulator;
    }
    function baseTimes2(n, iteratee2) {
      var index = -1, result2 = Array(n);
      while (++index < n) {
        result2[index] = iteratee2(index);
      }
      return result2;
    }
    function getValue2(object, key) {
      return object == null ? void 0 : object[key];
    }
    function isHostObject(value) {
      var result2 = false;
      if (value != null && typeof value.toString != "function") {
        try {
          result2 = !!(value + "");
        } catch (e) {
        }
      }
      return result2;
    }
    function mapToArray2(map2) {
      var index = -1, result2 = Array(map2.size);
      map2.forEach(function(value, key) {
        result2[++index] = [key, value];
      });
      return result2;
    }
    function overArg2(func, transform2) {
      return function(arg) {
        return func(transform2(arg));
      };
    }
    function setToArray2(set2) {
      var index = -1, result2 = Array(set2.size);
      set2.forEach(function(value) {
        result2[++index] = value;
      });
      return result2;
    }
    var arrayProto7 = Array.prototype;
    var funcProto4 = Function.prototype;
    var objectProto30 = Object.prototype;
    var coreJsData2 = root2["__core-js_shared__"];
    var maskSrcKey2 = function() {
      var uid = /[^.]+$/.exec(coreJsData2 && coreJsData2.keys && coreJsData2.keys.IE_PROTO || "");
      return uid ? "Symbol(src)_1." + uid : "";
    }();
    var funcToString4 = funcProto4.toString;
    var hasOwnProperty26 = objectProto30.hasOwnProperty;
    var objectToString2 = objectProto30.toString;
    var reIsNative2 = RegExp("^" + funcToString4.call(hasOwnProperty26).replace(reRegExpChar3, "\\$&").replace(/hasOwnProperty|(function).*?(?=\\\()| for .+?(?=\\\])/g, "$1.*?") + "$");
    var Buffer3 = moduleExports4 ? root2.Buffer : void 0;
    var Symbol2 = root2.Symbol;
    var Uint8Array2 = root2.Uint8Array;
    var getPrototype2 = overArg2(Object.getPrototypeOf, Object);
    var objectCreate2 = Object.create;
    var propertyIsEnumerable3 = objectProto30.propertyIsEnumerable;
    var splice4 = arrayProto7.splice;
    var nativeGetSymbols3 = Object.getOwnPropertySymbols;
    var nativeIsBuffer2 = Buffer3 ? Buffer3.isBuffer : void 0;
    var nativeKeys2 = overArg2(Object.keys, Object);
    var DataView2 = getNative2(root2, "DataView");
    var Map2 = getNative2(root2, "Map");
    var Promise3 = getNative2(root2, "Promise");
    var Set2 = getNative2(root2, "Set");
    var WeakMap3 = getNative2(root2, "WeakMap");
    var nativeCreate2 = getNative2(Object, "create");
    var dataViewCtorString2 = toSource2(DataView2);
    var mapCtorString2 = toSource2(Map2);
    var promiseCtorString2 = toSource2(Promise3);
    var setCtorString2 = toSource2(Set2);
    var weakMapCtorString2 = toSource2(WeakMap3);
    var symbolProto4 = Symbol2 ? Symbol2.prototype : void 0;
    var symbolValueOf3 = symbolProto4 ? symbolProto4.valueOf : void 0;
    function Hash2(entries) {
      var index = -1, length = entries ? entries.length : 0;
      this.clear();
      while (++index < length) {
        var entry = entries[index];
        this.set(entry[0], entry[1]);
      }
    }
    function hashClear2() {
      this.__data__ = nativeCreate2 ? nativeCreate2(null) : {};
    }
    function hashDelete2(key) {
      return this.has(key) && delete this.__data__[key];
    }
    function hashGet2(key) {
      var data = this.__data__;
      if (nativeCreate2) {
        var result2 = data[key];
        return result2 === HASH_UNDEFINED4 ? void 0 : result2;
      }
      return hasOwnProperty26.call(data, key) ? data[key] : void 0;
    }
    function hashHas2(key) {
      var data = this.__data__;
      return nativeCreate2 ? data[key] !== void 0 : hasOwnProperty26.call(data, key);
    }
    function hashSet2(key, value) {
      var data = this.__data__;
      data[key] = nativeCreate2 && value === void 0 ? HASH_UNDEFINED4 : value;
      return this;
    }
    Hash2.prototype.clear = hashClear2;
    Hash2.prototype["delete"] = hashDelete2;
    Hash2.prototype.get = hashGet2;
    Hash2.prototype.has = hashHas2;
    Hash2.prototype.set = hashSet2;
    function ListCache2(entries) {
      var index = -1, length = entries ? entries.length : 0;
      this.clear();
      while (++index < length) {
        var entry = entries[index];
        this.set(entry[0], entry[1]);
      }
    }
    function listCacheClear2() {
      this.__data__ = [];
    }
    function listCacheDelete2(key) {
      var data = this.__data__, index = assocIndexOf2(data, key);
      if (index < 0) {
        return false;
      }
      var lastIndex = data.length - 1;
      if (index == lastIndex) {
        data.pop();
      } else {
        splice4.call(data, index, 1);
      }
      return true;
    }
    function listCacheGet2(key) {
      var data = this.__data__, index = assocIndexOf2(data, key);
      return index < 0 ? void 0 : data[index][1];
    }
    function listCacheHas2(key) {
      return assocIndexOf2(this.__data__, key) > -1;
    }
    function listCacheSet2(key, value) {
      var data = this.__data__, index = assocIndexOf2(data, key);
      if (index < 0) {
        data.push([key, value]);
      } else {
        data[index][1] = value;
      }
      return this;
    }
    ListCache2.prototype.clear = listCacheClear2;
    ListCache2.prototype["delete"] = listCacheDelete2;
    ListCache2.prototype.get = listCacheGet2;
    ListCache2.prototype.has = listCacheHas2;
    ListCache2.prototype.set = listCacheSet2;
    function MapCache2(entries) {
      var index = -1, length = entries ? entries.length : 0;
      this.clear();
      while (++index < length) {
        var entry = entries[index];
        this.set(entry[0], entry[1]);
      }
    }
    function mapCacheClear2() {
      this.__data__ = {
        "hash": new Hash2(),
        "map": new (Map2 || ListCache2)(),
        "string": new Hash2()
      };
    }
    function mapCacheDelete2(key) {
      return getMapData2(this, key)["delete"](key);
    }
    function mapCacheGet2(key) {
      return getMapData2(this, key).get(key);
    }
    function mapCacheHas2(key) {
      return getMapData2(this, key).has(key);
    }
    function mapCacheSet2(key, value) {
      getMapData2(this, key).set(key, value);
      return this;
    }
    MapCache2.prototype.clear = mapCacheClear2;
    MapCache2.prototype["delete"] = mapCacheDelete2;
    MapCache2.prototype.get = mapCacheGet2;
    MapCache2.prototype.has = mapCacheHas2;
    MapCache2.prototype.set = mapCacheSet2;
    function Stack2(entries) {
      this.__data__ = new ListCache2(entries);
    }
    function stackClear2() {
      this.__data__ = new ListCache2();
    }
    function stackDelete2(key) {
      return this.__data__["delete"](key);
    }
    function stackGet2(key) {
      return this.__data__.get(key);
    }
    function stackHas2(key) {
      return this.__data__.has(key);
    }
    function stackSet2(key, value) {
      var cache = this.__data__;
      if (cache instanceof ListCache2) {
        var pairs = cache.__data__;
        if (!Map2 || pairs.length < LARGE_ARRAY_SIZE4 - 1) {
          pairs.push([key, value]);
          return this;
        }
        cache = this.__data__ = new MapCache2(pairs);
      }
      cache.set(key, value);
      return this;
    }
    Stack2.prototype.clear = stackClear2;
    Stack2.prototype["delete"] = stackDelete2;
    Stack2.prototype.get = stackGet2;
    Stack2.prototype.has = stackHas2;
    Stack2.prototype.set = stackSet2;
    function arrayLikeKeys2(value, inherited) {
      var result2 = isArray2(value) || isArguments2(value) ? baseTimes2(value.length, String) : [];
      var length = result2.length, skipIndexes = !!length;
      for (var key in value) {
        if ((inherited || hasOwnProperty26.call(value, key)) && !(skipIndexes && (key == "length" || isIndex2(key, length)))) {
          result2.push(key);
        }
      }
      return result2;
    }
    function assignValue2(object, key, value) {
      var objValue = object[key];
      if (!(hasOwnProperty26.call(object, key) && eq2(objValue, value)) || value === void 0 && !(key in object)) {
        object[key] = value;
      }
    }
    function assocIndexOf2(array, key) {
      var length = array.length;
      while (length--) {
        if (eq2(array[length][0], key)) {
          return length;
        }
      }
      return -1;
    }
    function baseAssign2(object, source) {
      return object && copyObject2(source, keys2(source), object);
    }
    function baseClone2(value, isDeep, isFull, customizer, key, object, stack) {
      var result2;
      if (customizer) {
        result2 = object ? customizer(value, key, object, stack) : customizer(value);
      }
      if (result2 !== void 0) {
        return result2;
      }
      if (!isObject2(value)) {
        return value;
      }
      var isArr = isArray2(value);
      if (isArr) {
        result2 = initCloneArray2(value);
        if (!isDeep) {
          return copyArray2(value, result2);
        }
      } else {
        var tag = getTag2(value), isFunc = tag == funcTag4 || tag == genTag3;
        if (isBuffer2(value)) {
          return cloneBuffer2(value, isDeep);
        }
        if (tag == objectTag6 || tag == argsTag5 || isFunc && !object) {
          if (isHostObject(value)) {
            return object ? value : {};
          }
          result2 = initCloneObject2(isFunc ? {} : value);
          if (!isDeep) {
            return copySymbols2(value, baseAssign2(result2, value));
          }
        } else {
          if (!cloneableTags2[tag]) {
            return object ? value : {};
          }
          result2 = initCloneByTag2(value, tag, baseClone2, isDeep);
        }
      }
      stack || (stack = new Stack2());
      var stacked = stack.get(value);
      if (stacked) {
        return stacked;
      }
      stack.set(value, result2);
      if (!isArr) {
        var props = isFull ? getAllKeys2(value) : keys2(value);
      }
      arrayEach2(props || value, function(subValue, key2) {
        if (props) {
          key2 = subValue;
          subValue = value[key2];
        }
        assignValue2(result2, key2, baseClone2(subValue, isDeep, isFull, customizer, key2, value, stack));
      });
      return result2;
    }
    function baseCreate2(proto) {
      return isObject2(proto) ? objectCreate2(proto) : {};
    }
    function baseGetAllKeys2(object, keysFunc, symbolsFunc) {
      var result2 = keysFunc(object);
      return isArray2(object) ? result2 : arrayPush2(result2, symbolsFunc(object));
    }
    function baseGetTag2(value) {
      return objectToString2.call(value);
    }
    function baseIsNative2(value) {
      if (!isObject2(value) || isMasked2(value)) {
        return false;
      }
      var pattern = isFunction2(value) || isHostObject(value) ? reIsNative2 : reIsHostCtor2;
      return pattern.test(toSource2(value));
    }
    function baseKeys2(object) {
      if (!isPrototype2(object)) {
        return nativeKeys2(object);
      }
      var result2 = [];
      for (var key in Object(object)) {
        if (hasOwnProperty26.call(object, key) && key != "constructor") {
          result2.push(key);
        }
      }
      return result2;
    }
    function cloneBuffer2(buffer, isDeep) {
      if (isDeep) {
        return buffer.slice();
      }
      var result2 = new buffer.constructor(buffer.length);
      buffer.copy(result2);
      return result2;
    }
    function cloneArrayBuffer2(arrayBuffer) {
      var result2 = new arrayBuffer.constructor(arrayBuffer.byteLength);
      new Uint8Array2(result2).set(new Uint8Array2(arrayBuffer));
      return result2;
    }
    function cloneDataView2(dataView, isDeep) {
      var buffer = isDeep ? cloneArrayBuffer2(dataView.buffer) : dataView.buffer;
      return new dataView.constructor(buffer, dataView.byteOffset, dataView.byteLength);
    }
    function cloneMap(map2, isDeep, cloneFunc) {
      var array = isDeep ? cloneFunc(mapToArray2(map2), true) : mapToArray2(map2);
      return arrayReduce2(array, addMapEntry, new map2.constructor());
    }
    function cloneRegExp2(regexp) {
      var result2 = new regexp.constructor(regexp.source, reFlags3.exec(regexp));
      result2.lastIndex = regexp.lastIndex;
      return result2;
    }
    function cloneSet(set2, isDeep, cloneFunc) {
      var array = isDeep ? cloneFunc(setToArray2(set2), true) : setToArray2(set2);
      return arrayReduce2(array, addSetEntry, new set2.constructor());
    }
    function cloneSymbol2(symbol) {
      return symbolValueOf3 ? Object(symbolValueOf3.call(symbol)) : {};
    }
    function cloneTypedArray2(typedArray, isDeep) {
      var buffer = isDeep ? cloneArrayBuffer2(typedArray.buffer) : typedArray.buffer;
      return new typedArray.constructor(buffer, typedArray.byteOffset, typedArray.length);
    }
    function copyArray2(source, array) {
      var index = -1, length = source.length;
      array || (array = Array(length));
      while (++index < length) {
        array[index] = source[index];
      }
      return array;
    }
    function copyObject2(source, props, object, customizer) {
      object || (object = {});
      var index = -1, length = props.length;
      while (++index < length) {
        var key = props[index];
        var newValue = customizer ? customizer(object[key], source[key], key, object, source) : void 0;
        assignValue2(object, key, newValue === void 0 ? source[key] : newValue);
      }
      return object;
    }
    function copySymbols2(source, object) {
      return copyObject2(source, getSymbols2(source), object);
    }
    function getAllKeys2(object) {
      return baseGetAllKeys2(object, keys2, getSymbols2);
    }
    function getMapData2(map2, key) {
      var data = map2.__data__;
      return isKeyable2(key) ? data[typeof key == "string" ? "string" : "hash"] : data.map;
    }
    function getNative2(object, key) {
      var value = getValue2(object, key);
      return baseIsNative2(value) ? value : void 0;
    }
    var getSymbols2 = nativeGetSymbols3 ? overArg2(nativeGetSymbols3, Object) : stubArray2;
    var getTag2 = baseGetTag2;
    if (DataView2 && getTag2(new DataView2(new ArrayBuffer(1))) != dataViewTag6 || Map2 && getTag2(new Map2()) != mapTag11 || Promise3 && getTag2(Promise3.resolve()) != promiseTag2 || Set2 && getTag2(new Set2()) != setTag11 || WeakMap3 && getTag2(new WeakMap3()) != weakMapTag5) {
      getTag2 = function(value) {
        var result2 = objectToString2.call(value), Ctor = result2 == objectTag6 ? value.constructor : void 0, ctorString = Ctor ? toSource2(Ctor) : void 0;
        if (ctorString) {
          switch (ctorString) {
            case dataViewCtorString2:
              return dataViewTag6;
            case mapCtorString2:
              return mapTag11;
            case promiseCtorString2:
              return promiseTag2;
            case setCtorString2:
              return setTag11;
            case weakMapCtorString2:
              return weakMapTag5;
          }
        }
        return result2;
      };
    }
    function initCloneArray2(array) {
      var length = array.length, result2 = array.constructor(length);
      if (length && typeof array[0] == "string" && hasOwnProperty26.call(array, "index")) {
        result2.index = array.index;
        result2.input = array.input;
      }
      return result2;
    }
    function initCloneObject2(object) {
      return typeof object.constructor == "function" && !isPrototype2(object) ? baseCreate2(getPrototype2(object)) : {};
    }
    function initCloneByTag2(object, tag, cloneFunc, isDeep) {
      var Ctor = object.constructor;
      switch (tag) {
        case arrayBufferTag6:
          return cloneArrayBuffer2(object);
        case boolTag6:
        case dateTag6:
          return new Ctor(+object);
        case dataViewTag6:
          return cloneDataView2(object, isDeep);
        case float32Tag4:
        case float64Tag4:
        case int8Tag4:
        case int16Tag4:
        case int32Tag4:
        case uint8Tag4:
        case uint8ClampedTag4:
        case uint16Tag4:
        case uint32Tag4:
          return cloneTypedArray2(object, isDeep);
        case mapTag11:
          return cloneMap(object, isDeep, cloneFunc);
        case numberTag6:
        case stringTag6:
          return new Ctor(object);
        case regexpTag6:
          return cloneRegExp2(object);
        case setTag11:
          return cloneSet(object, isDeep, cloneFunc);
        case symbolTag5:
          return cloneSymbol2(object);
      }
    }
    function isIndex2(value, length) {
      length = length == null ? MAX_SAFE_INTEGER7 : length;
      return !!length && (typeof value == "number" || reIsUint2.test(value)) && value > -1 && value % 1 == 0 && value < length;
    }
    function isKeyable2(value) {
      var type = typeof value;
      return type == "string" || type == "number" || type == "symbol" || type == "boolean" ? value !== "__proto__" : value === null;
    }
    function isMasked2(func) {
      return !!maskSrcKey2 && maskSrcKey2 in func;
    }
    function isPrototype2(value) {
      var Ctor = value && value.constructor, proto = typeof Ctor == "function" && Ctor.prototype || objectProto30;
      return value === proto;
    }
    function toSource2(func) {
      if (func != null) {
        try {
          return funcToString4.call(func);
        } catch (e) {
        }
        try {
          return func + "";
        } catch (e) {
        }
      }
      return "";
    }
    function cloneDeep2(value) {
      return baseClone2(value, true, true);
    }
    function eq2(value, other) {
      return value === other || value !== value && other !== other;
    }
    function isArguments2(value) {
      return isArrayLikeObject2(value) && hasOwnProperty26.call(value, "callee") && (!propertyIsEnumerable3.call(value, "callee") || objectToString2.call(value) == argsTag5);
    }
    var isArray2 = Array.isArray;
    function isArrayLike2(value) {
      return value != null && isLength2(value.length) && !isFunction2(value);
    }
    function isArrayLikeObject2(value) {
      return isObjectLike2(value) && isArrayLike2(value);
    }
    var isBuffer2 = nativeIsBuffer2 || stubFalse2;
    function isFunction2(value) {
      var tag = isObject2(value) ? objectToString2.call(value) : "";
      return tag == funcTag4 || tag == genTag3;
    }
    function isLength2(value) {
      return typeof value == "number" && value > -1 && value % 1 == 0 && value <= MAX_SAFE_INTEGER7;
    }
    function isObject2(value) {
      var type = typeof value;
      return !!value && (type == "object" || type == "function");
    }
    function isObjectLike2(value) {
      return !!value && typeof value == "object";
    }
    function keys2(object) {
      return isArrayLike2(object) ? arrayLikeKeys2(object) : baseKeys2(object);
    }
    function stubArray2() {
      return [];
    }
    function stubFalse2() {
      return false;
    }
    module2.exports = cloneDeep2;
  }
});

// node_modules/lodash.isequal/index.js
var require_lodash2 = __commonJS({
  "node_modules/lodash.isequal/index.js"(exports2, module2) {
    var LARGE_ARRAY_SIZE4 = 200;
    var HASH_UNDEFINED4 = "__lodash_hash_undefined__";
    var COMPARE_PARTIAL_FLAG7 = 1;
    var COMPARE_UNORDERED_FLAG5 = 2;
    var MAX_SAFE_INTEGER7 = 9007199254740991;
    var argsTag5 = "[object Arguments]";
    var arrayTag4 = "[object Array]";
    var asyncTag2 = "[object AsyncFunction]";
    var boolTag6 = "[object Boolean]";
    var dateTag6 = "[object Date]";
    var errorTag5 = "[object Error]";
    var funcTag4 = "[object Function]";
    var genTag3 = "[object GeneratorFunction]";
    var mapTag11 = "[object Map]";
    var numberTag6 = "[object Number]";
    var nullTag2 = "[object Null]";
    var objectTag6 = "[object Object]";
    var promiseTag2 = "[object Promise]";
    var proxyTag2 = "[object Proxy]";
    var regexpTag6 = "[object RegExp]";
    var setTag11 = "[object Set]";
    var stringTag6 = "[object String]";
    var symbolTag5 = "[object Symbol]";
    var undefinedTag2 = "[object Undefined]";
    var weakMapTag5 = "[object WeakMap]";
    var arrayBufferTag6 = "[object ArrayBuffer]";
    var dataViewTag6 = "[object DataView]";
    var float32Tag4 = "[object Float32Array]";
    var float64Tag4 = "[object Float64Array]";
    var int8Tag4 = "[object Int8Array]";
    var int16Tag4 = "[object Int16Array]";
    var int32Tag4 = "[object Int32Array]";
    var uint8Tag4 = "[object Uint8Array]";
    var uint8ClampedTag4 = "[object Uint8ClampedArray]";
    var uint16Tag4 = "[object Uint16Array]";
    var uint32Tag4 = "[object Uint32Array]";
    var reRegExpChar3 = /[\\^$.*+?()[\]{}|]/g;
    var reIsHostCtor2 = /^\[object .+?Constructor\]$/;
    var reIsUint2 = /^(?:0|[1-9]\d*)$/;
    var typedArrayTags2 = {};
    typedArrayTags2[float32Tag4] = typedArrayTags2[float64Tag4] = typedArrayTags2[int8Tag4] = typedArrayTags2[int16Tag4] = typedArrayTags2[int32Tag4] = typedArrayTags2[uint8Tag4] = typedArrayTags2[uint8ClampedTag4] = typedArrayTags2[uint16Tag4] = typedArrayTags2[uint32Tag4] = true;
    typedArrayTags2[argsTag5] = typedArrayTags2[arrayTag4] = typedArrayTags2[arrayBufferTag6] = typedArrayTags2[boolTag6] = typedArrayTags2[dataViewTag6] = typedArrayTags2[dateTag6] = typedArrayTags2[errorTag5] = typedArrayTags2[funcTag4] = typedArrayTags2[mapTag11] = typedArrayTags2[numberTag6] = typedArrayTags2[objectTag6] = typedArrayTags2[regexpTag6] = typedArrayTags2[setTag11] = typedArrayTags2[stringTag6] = typedArrayTags2[weakMapTag5] = false;
    var freeGlobal2 = typeof global == "object" && global && global.Object === Object && global;
    var freeSelf2 = typeof self == "object" && self && self.Object === Object && self;
    var root2 = freeGlobal2 || freeSelf2 || Function("return this")();
    var freeExports4 = typeof exports2 == "object" && exports2 && !exports2.nodeType && exports2;
    var freeModule4 = freeExports4 && typeof module2 == "object" && module2 && !module2.nodeType && module2;
    var moduleExports4 = freeModule4 && freeModule4.exports === freeExports4;
    var freeProcess2 = moduleExports4 && freeGlobal2.process;
    var nodeUtil2 = function() {
      try {
        return freeProcess2 && freeProcess2.binding && freeProcess2.binding("util");
      } catch (e) {
      }
    }();
    var nodeIsTypedArray2 = nodeUtil2 && nodeUtil2.isTypedArray;
    function arrayFilter2(array, predicate) {
      var index = -1, length = array == null ? 0 : array.length, resIndex = 0, result2 = [];
      while (++index < length) {
        var value = array[index];
        if (predicate(value, index, array)) {
          result2[resIndex++] = value;
        }
      }
      return result2;
    }
    function arrayPush2(array, values2) {
      var index = -1, length = values2.length, offset = array.length;
      while (++index < length) {
        array[offset + index] = values2[index];
      }
      return array;
    }
    function arraySome2(array, predicate) {
      var index = -1, length = array == null ? 0 : array.length;
      while (++index < length) {
        if (predicate(array[index], index, array)) {
          return true;
        }
      }
      return false;
    }
    function baseTimes2(n, iteratee2) {
      var index = -1, result2 = Array(n);
      while (++index < n) {
        result2[index] = iteratee2(index);
      }
      return result2;
    }
    function baseUnary2(func) {
      return function(value) {
        return func(value);
      };
    }
    function cacheHas2(cache, key) {
      return cache.has(key);
    }
    function getValue2(object, key) {
      return object == null ? void 0 : object[key];
    }
    function mapToArray2(map2) {
      var index = -1, result2 = Array(map2.size);
      map2.forEach(function(value, key) {
        result2[++index] = [key, value];
      });
      return result2;
    }
    function overArg2(func, transform2) {
      return function(arg) {
        return func(transform2(arg));
      };
    }
    function setToArray2(set2) {
      var index = -1, result2 = Array(set2.size);
      set2.forEach(function(value) {
        result2[++index] = value;
      });
      return result2;
    }
    var arrayProto7 = Array.prototype;
    var funcProto4 = Function.prototype;
    var objectProto30 = Object.prototype;
    var coreJsData2 = root2["__core-js_shared__"];
    var funcToString4 = funcProto4.toString;
    var hasOwnProperty26 = objectProto30.hasOwnProperty;
    var maskSrcKey2 = function() {
      var uid = /[^.]+$/.exec(coreJsData2 && coreJsData2.keys && coreJsData2.keys.IE_PROTO || "");
      return uid ? "Symbol(src)_1." + uid : "";
    }();
    var nativeObjectToString5 = objectProto30.toString;
    var reIsNative2 = RegExp("^" + funcToString4.call(hasOwnProperty26).replace(reRegExpChar3, "\\$&").replace(/hasOwnProperty|(function).*?(?=\\\()| for .+?(?=\\\])/g, "$1.*?") + "$");
    var Buffer3 = moduleExports4 ? root2.Buffer : void 0;
    var Symbol2 = root2.Symbol;
    var Uint8Array2 = root2.Uint8Array;
    var propertyIsEnumerable3 = objectProto30.propertyIsEnumerable;
    var splice4 = arrayProto7.splice;
    var symToStringTag3 = Symbol2 ? Symbol2.toStringTag : void 0;
    var nativeGetSymbols3 = Object.getOwnPropertySymbols;
    var nativeIsBuffer2 = Buffer3 ? Buffer3.isBuffer : void 0;
    var nativeKeys2 = overArg2(Object.keys, Object);
    var DataView2 = getNative2(root2, "DataView");
    var Map2 = getNative2(root2, "Map");
    var Promise3 = getNative2(root2, "Promise");
    var Set2 = getNative2(root2, "Set");
    var WeakMap3 = getNative2(root2, "WeakMap");
    var nativeCreate2 = getNative2(Object, "create");
    var dataViewCtorString2 = toSource2(DataView2);
    var mapCtorString2 = toSource2(Map2);
    var promiseCtorString2 = toSource2(Promise3);
    var setCtorString2 = toSource2(Set2);
    var weakMapCtorString2 = toSource2(WeakMap3);
    var symbolProto4 = Symbol2 ? Symbol2.prototype : void 0;
    var symbolValueOf3 = symbolProto4 ? symbolProto4.valueOf : void 0;
    function Hash2(entries) {
      var index = -1, length = entries == null ? 0 : entries.length;
      this.clear();
      while (++index < length) {
        var entry = entries[index];
        this.set(entry[0], entry[1]);
      }
    }
    function hashClear2() {
      this.__data__ = nativeCreate2 ? nativeCreate2(null) : {};
      this.size = 0;
    }
    function hashDelete2(key) {
      var result2 = this.has(key) && delete this.__data__[key];
      this.size -= result2 ? 1 : 0;
      return result2;
    }
    function hashGet2(key) {
      var data = this.__data__;
      if (nativeCreate2) {
        var result2 = data[key];
        return result2 === HASH_UNDEFINED4 ? void 0 : result2;
      }
      return hasOwnProperty26.call(data, key) ? data[key] : void 0;
    }
    function hashHas2(key) {
      var data = this.__data__;
      return nativeCreate2 ? data[key] !== void 0 : hasOwnProperty26.call(data, key);
    }
    function hashSet2(key, value) {
      var data = this.__data__;
      this.size += this.has(key) ? 0 : 1;
      data[key] = nativeCreate2 && value === void 0 ? HASH_UNDEFINED4 : value;
      return this;
    }
    Hash2.prototype.clear = hashClear2;
    Hash2.prototype["delete"] = hashDelete2;
    Hash2.prototype.get = hashGet2;
    Hash2.prototype.has = hashHas2;
    Hash2.prototype.set = hashSet2;
    function ListCache2(entries) {
      var index = -1, length = entries == null ? 0 : entries.length;
      this.clear();
      while (++index < length) {
        var entry = entries[index];
        this.set(entry[0], entry[1]);
      }
    }
    function listCacheClear2() {
      this.__data__ = [];
      this.size = 0;
    }
    function listCacheDelete2(key) {
      var data = this.__data__, index = assocIndexOf2(data, key);
      if (index < 0) {
        return false;
      }
      var lastIndex = data.length - 1;
      if (index == lastIndex) {
        data.pop();
      } else {
        splice4.call(data, index, 1);
      }
      --this.size;
      return true;
    }
    function listCacheGet2(key) {
      var data = this.__data__, index = assocIndexOf2(data, key);
      return index < 0 ? void 0 : data[index][1];
    }
    function listCacheHas2(key) {
      return assocIndexOf2(this.__data__, key) > -1;
    }
    function listCacheSet2(key, value) {
      var data = this.__data__, index = assocIndexOf2(data, key);
      if (index < 0) {
        ++this.size;
        data.push([key, value]);
      } else {
        data[index][1] = value;
      }
      return this;
    }
    ListCache2.prototype.clear = listCacheClear2;
    ListCache2.prototype["delete"] = listCacheDelete2;
    ListCache2.prototype.get = listCacheGet2;
    ListCache2.prototype.has = listCacheHas2;
    ListCache2.prototype.set = listCacheSet2;
    function MapCache2(entries) {
      var index = -1, length = entries == null ? 0 : entries.length;
      this.clear();
      while (++index < length) {
        var entry = entries[index];
        this.set(entry[0], entry[1]);
      }
    }
    function mapCacheClear2() {
      this.size = 0;
      this.__data__ = {
        "hash": new Hash2(),
        "map": new (Map2 || ListCache2)(),
        "string": new Hash2()
      };
    }
    function mapCacheDelete2(key) {
      var result2 = getMapData2(this, key)["delete"](key);
      this.size -= result2 ? 1 : 0;
      return result2;
    }
    function mapCacheGet2(key) {
      return getMapData2(this, key).get(key);
    }
    function mapCacheHas2(key) {
      return getMapData2(this, key).has(key);
    }
    function mapCacheSet2(key, value) {
      var data = getMapData2(this, key), size2 = data.size;
      data.set(key, value);
      this.size += data.size == size2 ? 0 : 1;
      return this;
    }
    MapCache2.prototype.clear = mapCacheClear2;
    MapCache2.prototype["delete"] = mapCacheDelete2;
    MapCache2.prototype.get = mapCacheGet2;
    MapCache2.prototype.has = mapCacheHas2;
    MapCache2.prototype.set = mapCacheSet2;
    function SetCache2(values2) {
      var index = -1, length = values2 == null ? 0 : values2.length;
      this.__data__ = new MapCache2();
      while (++index < length) {
        this.add(values2[index]);
      }
    }
    function setCacheAdd2(value) {
      this.__data__.set(value, HASH_UNDEFINED4);
      return this;
    }
    function setCacheHas2(value) {
      return this.__data__.has(value);
    }
    SetCache2.prototype.add = SetCache2.prototype.push = setCacheAdd2;
    SetCache2.prototype.has = setCacheHas2;
    function Stack2(entries) {
      var data = this.__data__ = new ListCache2(entries);
      this.size = data.size;
    }
    function stackClear2() {
      this.__data__ = new ListCache2();
      this.size = 0;
    }
    function stackDelete2(key) {
      var data = this.__data__, result2 = data["delete"](key);
      this.size = data.size;
      return result2;
    }
    function stackGet2(key) {
      return this.__data__.get(key);
    }
    function stackHas2(key) {
      return this.__data__.has(key);
    }
    function stackSet2(key, value) {
      var data = this.__data__;
      if (data instanceof ListCache2) {
        var pairs = data.__data__;
        if (!Map2 || pairs.length < LARGE_ARRAY_SIZE4 - 1) {
          pairs.push([key, value]);
          this.size = ++data.size;
          return this;
        }
        data = this.__data__ = new MapCache2(pairs);
      }
      data.set(key, value);
      this.size = data.size;
      return this;
    }
    Stack2.prototype.clear = stackClear2;
    Stack2.prototype["delete"] = stackDelete2;
    Stack2.prototype.get = stackGet2;
    Stack2.prototype.has = stackHas2;
    Stack2.prototype.set = stackSet2;
    function arrayLikeKeys2(value, inherited) {
      var isArr = isArray2(value), isArg = !isArr && isArguments2(value), isBuff = !isArr && !isArg && isBuffer2(value), isType = !isArr && !isArg && !isBuff && isTypedArray2(value), skipIndexes = isArr || isArg || isBuff || isType, result2 = skipIndexes ? baseTimes2(value.length, String) : [], length = result2.length;
      for (var key in value) {
        if ((inherited || hasOwnProperty26.call(value, key)) && !(skipIndexes && // Safari 9 has enumerable `arguments.length` in strict mode.
        (key == "length" || // Node.js 0.10 has enumerable non-index properties on buffers.
        isBuff && (key == "offset" || key == "parent") || // PhantomJS 2 has enumerable non-index properties on typed arrays.
        isType && (key == "buffer" || key == "byteLength" || key == "byteOffset") || // Skip index properties.
        isIndex2(key, length)))) {
          result2.push(key);
        }
      }
      return result2;
    }
    function assocIndexOf2(array, key) {
      var length = array.length;
      while (length--) {
        if (eq2(array[length][0], key)) {
          return length;
        }
      }
      return -1;
    }
    function baseGetAllKeys2(object, keysFunc, symbolsFunc) {
      var result2 = keysFunc(object);
      return isArray2(object) ? result2 : arrayPush2(result2, symbolsFunc(object));
    }
    function baseGetTag2(value) {
      if (value == null) {
        return value === void 0 ? undefinedTag2 : nullTag2;
      }
      return symToStringTag3 && symToStringTag3 in Object(value) ? getRawTag2(value) : objectToString2(value);
    }
    function baseIsArguments2(value) {
      return isObjectLike2(value) && baseGetTag2(value) == argsTag5;
    }
    function baseIsEqual2(value, other, bitmask, customizer, stack) {
      if (value === other) {
        return true;
      }
      if (value == null || other == null || !isObjectLike2(value) && !isObjectLike2(other)) {
        return value !== value && other !== other;
      }
      return baseIsEqualDeep2(value, other, bitmask, customizer, baseIsEqual2, stack);
    }
    function baseIsEqualDeep2(object, other, bitmask, customizer, equalFunc, stack) {
      var objIsArr = isArray2(object), othIsArr = isArray2(other), objTag = objIsArr ? arrayTag4 : getTag2(object), othTag = othIsArr ? arrayTag4 : getTag2(other);
      objTag = objTag == argsTag5 ? objectTag6 : objTag;
      othTag = othTag == argsTag5 ? objectTag6 : othTag;
      var objIsObj = objTag == objectTag6, othIsObj = othTag == objectTag6, isSameTag = objTag == othTag;
      if (isSameTag && isBuffer2(object)) {
        if (!isBuffer2(other)) {
          return false;
        }
        objIsArr = true;
        objIsObj = false;
      }
      if (isSameTag && !objIsObj) {
        stack || (stack = new Stack2());
        return objIsArr || isTypedArray2(object) ? equalArrays2(object, other, bitmask, customizer, equalFunc, stack) : equalByTag2(object, other, objTag, bitmask, customizer, equalFunc, stack);
      }
      if (!(bitmask & COMPARE_PARTIAL_FLAG7)) {
        var objIsWrapped = objIsObj && hasOwnProperty26.call(object, "__wrapped__"), othIsWrapped = othIsObj && hasOwnProperty26.call(other, "__wrapped__");
        if (objIsWrapped || othIsWrapped) {
          var objUnwrapped = objIsWrapped ? object.value() : object, othUnwrapped = othIsWrapped ? other.value() : other;
          stack || (stack = new Stack2());
          return equalFunc(objUnwrapped, othUnwrapped, bitmask, customizer, stack);
        }
      }
      if (!isSameTag) {
        return false;
      }
      stack || (stack = new Stack2());
      return equalObjects2(object, other, bitmask, customizer, equalFunc, stack);
    }
    function baseIsNative2(value) {
      if (!isObject2(value) || isMasked2(value)) {
        return false;
      }
      var pattern = isFunction2(value) ? reIsNative2 : reIsHostCtor2;
      return pattern.test(toSource2(value));
    }
    function baseIsTypedArray2(value) {
      return isObjectLike2(value) && isLength2(value.length) && !!typedArrayTags2[baseGetTag2(value)];
    }
    function baseKeys2(object) {
      if (!isPrototype2(object)) {
        return nativeKeys2(object);
      }
      var result2 = [];
      for (var key in Object(object)) {
        if (hasOwnProperty26.call(object, key) && key != "constructor") {
          result2.push(key);
        }
      }
      return result2;
    }
    function equalArrays2(array, other, bitmask, customizer, equalFunc, stack) {
      var isPartial = bitmask & COMPARE_PARTIAL_FLAG7, arrLength = array.length, othLength = other.length;
      if (arrLength != othLength && !(isPartial && othLength > arrLength)) {
        return false;
      }
      var stacked = stack.get(array);
      if (stacked && stack.get(other)) {
        return stacked == other;
      }
      var index = -1, result2 = true, seen = bitmask & COMPARE_UNORDERED_FLAG5 ? new SetCache2() : void 0;
      stack.set(array, other);
      stack.set(other, array);
      while (++index < arrLength) {
        var arrValue = array[index], othValue = other[index];
        if (customizer) {
          var compared = isPartial ? customizer(othValue, arrValue, index, other, array, stack) : customizer(arrValue, othValue, index, array, other, stack);
        }
        if (compared !== void 0) {
          if (compared) {
            continue;
          }
          result2 = false;
          break;
        }
        if (seen) {
          if (!arraySome2(other, function(othValue2, othIndex) {
            if (!cacheHas2(seen, othIndex) && (arrValue === othValue2 || equalFunc(arrValue, othValue2, bitmask, customizer, stack))) {
              return seen.push(othIndex);
            }
          })) {
            result2 = false;
            break;
          }
        } else if (!(arrValue === othValue || equalFunc(arrValue, othValue, bitmask, customizer, stack))) {
          result2 = false;
          break;
        }
      }
      stack["delete"](array);
      stack["delete"](other);
      return result2;
    }
    function equalByTag2(object, other, tag, bitmask, customizer, equalFunc, stack) {
      switch (tag) {
        case dataViewTag6:
          if (object.byteLength != other.byteLength || object.byteOffset != other.byteOffset) {
            return false;
          }
          object = object.buffer;
          other = other.buffer;
        case arrayBufferTag6:
          if (object.byteLength != other.byteLength || !equalFunc(new Uint8Array2(object), new Uint8Array2(other))) {
            return false;
          }
          return true;
        case boolTag6:
        case dateTag6:
        case numberTag6:
          return eq2(+object, +other);
        case errorTag5:
          return object.name == other.name && object.message == other.message;
        case regexpTag6:
        case stringTag6:
          return object == other + "";
        case mapTag11:
          var convert = mapToArray2;
        case setTag11:
          var isPartial = bitmask & COMPARE_PARTIAL_FLAG7;
          convert || (convert = setToArray2);
          if (object.size != other.size && !isPartial) {
            return false;
          }
          var stacked = stack.get(object);
          if (stacked) {
            return stacked == other;
          }
          bitmask |= COMPARE_UNORDERED_FLAG5;
          stack.set(object, other);
          var result2 = equalArrays2(convert(object), convert(other), bitmask, customizer, equalFunc, stack);
          stack["delete"](object);
          return result2;
        case symbolTag5:
          if (symbolValueOf3) {
            return symbolValueOf3.call(object) == symbolValueOf3.call(other);
          }
      }
      return false;
    }
    function equalObjects2(object, other, bitmask, customizer, equalFunc, stack) {
      var isPartial = bitmask & COMPARE_PARTIAL_FLAG7, objProps = getAllKeys2(object), objLength = objProps.length, othProps = getAllKeys2(other), othLength = othProps.length;
      if (objLength != othLength && !isPartial) {
        return false;
      }
      var index = objLength;
      while (index--) {
        var key = objProps[index];
        if (!(isPartial ? key in other : hasOwnProperty26.call(other, key))) {
          return false;
        }
      }
      var stacked = stack.get(object);
      if (stacked && stack.get(other)) {
        return stacked == other;
      }
      var result2 = true;
      stack.set(object, other);
      stack.set(other, object);
      var skipCtor = isPartial;
      while (++index < objLength) {
        key = objProps[index];
        var objValue = object[key], othValue = other[key];
        if (customizer) {
          var compared = isPartial ? customizer(othValue, objValue, key, other, object, stack) : customizer(objValue, othValue, key, object, other, stack);
        }
        if (!(compared === void 0 ? objValue === othValue || equalFunc(objValue, othValue, bitmask, customizer, stack) : compared)) {
          result2 = false;
          break;
        }
        skipCtor || (skipCtor = key == "constructor");
      }
      if (result2 && !skipCtor) {
        var objCtor = object.constructor, othCtor = other.constructor;
        if (objCtor != othCtor && "constructor" in object && "constructor" in other && !(typeof objCtor == "function" && objCtor instanceof objCtor && typeof othCtor == "function" && othCtor instanceof othCtor)) {
          result2 = false;
        }
      }
      stack["delete"](object);
      stack["delete"](other);
      return result2;
    }
    function getAllKeys2(object) {
      return baseGetAllKeys2(object, keys2, getSymbols2);
    }
    function getMapData2(map2, key) {
      var data = map2.__data__;
      return isKeyable2(key) ? data[typeof key == "string" ? "string" : "hash"] : data.map;
    }
    function getNative2(object, key) {
      var value = getValue2(object, key);
      return baseIsNative2(value) ? value : void 0;
    }
    function getRawTag2(value) {
      var isOwn = hasOwnProperty26.call(value, symToStringTag3), tag = value[symToStringTag3];
      try {
        value[symToStringTag3] = void 0;
        var unmasked = true;
      } catch (e) {
      }
      var result2 = nativeObjectToString5.call(value);
      if (unmasked) {
        if (isOwn) {
          value[symToStringTag3] = tag;
        } else {
          delete value[symToStringTag3];
        }
      }
      return result2;
    }
    var getSymbols2 = !nativeGetSymbols3 ? stubArray2 : function(object) {
      if (object == null) {
        return [];
      }
      object = Object(object);
      return arrayFilter2(nativeGetSymbols3(object), function(symbol) {
        return propertyIsEnumerable3.call(object, symbol);
      });
    };
    var getTag2 = baseGetTag2;
    if (DataView2 && getTag2(new DataView2(new ArrayBuffer(1))) != dataViewTag6 || Map2 && getTag2(new Map2()) != mapTag11 || Promise3 && getTag2(Promise3.resolve()) != promiseTag2 || Set2 && getTag2(new Set2()) != setTag11 || WeakMap3 && getTag2(new WeakMap3()) != weakMapTag5) {
      getTag2 = function(value) {
        var result2 = baseGetTag2(value), Ctor = result2 == objectTag6 ? value.constructor : void 0, ctorString = Ctor ? toSource2(Ctor) : "";
        if (ctorString) {
          switch (ctorString) {
            case dataViewCtorString2:
              return dataViewTag6;
            case mapCtorString2:
              return mapTag11;
            case promiseCtorString2:
              return promiseTag2;
            case setCtorString2:
              return setTag11;
            case weakMapCtorString2:
              return weakMapTag5;
          }
        }
        return result2;
      };
    }
    function isIndex2(value, length) {
      length = length == null ? MAX_SAFE_INTEGER7 : length;
      return !!length && (typeof value == "number" || reIsUint2.test(value)) && value > -1 && value % 1 == 0 && value < length;
    }
    function isKeyable2(value) {
      var type = typeof value;
      return type == "string" || type == "number" || type == "symbol" || type == "boolean" ? value !== "__proto__" : value === null;
    }
    function isMasked2(func) {
      return !!maskSrcKey2 && maskSrcKey2 in func;
    }
    function isPrototype2(value) {
      var Ctor = value && value.constructor, proto = typeof Ctor == "function" && Ctor.prototype || objectProto30;
      return value === proto;
    }
    function objectToString2(value) {
      return nativeObjectToString5.call(value);
    }
    function toSource2(func) {
      if (func != null) {
        try {
          return funcToString4.call(func);
        } catch (e) {
        }
        try {
          return func + "";
        } catch (e) {
        }
      }
      return "";
    }
    function eq2(value, other) {
      return value === other || value !== value && other !== other;
    }
    var isArguments2 = baseIsArguments2(/* @__PURE__ */ function() {
      return arguments;
    }()) ? baseIsArguments2 : function(value) {
      return isObjectLike2(value) && hasOwnProperty26.call(value, "callee") && !propertyIsEnumerable3.call(value, "callee");
    };
    var isArray2 = Array.isArray;
    function isArrayLike2(value) {
      return value != null && isLength2(value.length) && !isFunction2(value);
    }
    var isBuffer2 = nativeIsBuffer2 || stubFalse2;
    function isEqual3(value, other) {
      return baseIsEqual2(value, other);
    }
    function isFunction2(value) {
      if (!isObject2(value)) {
        return false;
      }
      var tag = baseGetTag2(value);
      return tag == funcTag4 || tag == genTag3 || tag == asyncTag2 || tag == proxyTag2;
    }
    function isLength2(value) {
      return typeof value == "number" && value > -1 && value % 1 == 0 && value <= MAX_SAFE_INTEGER7;
    }
    function isObject2(value) {
      var type = typeof value;
      return value != null && (type == "object" || type == "function");
    }
    function isObjectLike2(value) {
      return value != null && typeof value == "object";
    }
    var isTypedArray2 = nodeIsTypedArray2 ? baseUnary2(nodeIsTypedArray2) : baseIsTypedArray2;
    function keys2(object) {
      return isArrayLike2(object) ? arrayLikeKeys2(object) : baseKeys2(object);
    }
    function stubArray2() {
      return [];
    }
    function stubFalse2() {
      return false;
    }
    module2.exports = isEqual3;
  }
});

// node_modules/quill-delta/dist/AttributeMap.js
var require_AttributeMap = __commonJS({
  "node_modules/quill-delta/dist/AttributeMap.js"(exports2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", {
      value: true
    });
    var cloneDeep2 = require_lodash();
    var isEqual3 = require_lodash2();
    var AttributeMap5;
    (function(AttributeMap6) {
      function compose(a = {}, b = {}, keepNull = false) {
        if (typeof a !== "object") {
          a = {};
        }
        if (typeof b !== "object") {
          b = {};
        }
        let attributes = cloneDeep2(b);
        if (!keepNull) {
          attributes = Object.keys(attributes).reduce((copy, key) => {
            if (attributes[key] != null) {
              copy[key] = attributes[key];
            }
            return copy;
          }, {});
        }
        for (const key in a) {
          if (a[key] !== void 0 && b[key] === void 0) {
            attributes[key] = a[key];
          }
        }
        return Object.keys(attributes).length > 0 ? attributes : void 0;
      }
      AttributeMap6.compose = compose;
      function diff(a = {}, b = {}) {
        if (typeof a !== "object") {
          a = {};
        }
        if (typeof b !== "object") {
          b = {};
        }
        const attributes = Object.keys(a).concat(Object.keys(b)).reduce((attrs, key) => {
          if (!isEqual3(a[key], b[key])) {
            attrs[key] = b[key] === void 0 ? null : b[key];
          }
          return attrs;
        }, {});
        return Object.keys(attributes).length > 0 ? attributes : void 0;
      }
      AttributeMap6.diff = diff;
      function invert2(attr = {}, base = {}) {
        attr = attr || {};
        const baseInverted = Object.keys(base).reduce((memo, key) => {
          if (base[key] !== attr[key] && attr[key] !== void 0) {
            memo[key] = base[key];
          }
          return memo;
        }, {});
        return Object.keys(attr).reduce((memo, key) => {
          if (attr[key] !== base[key] && base[key] === void 0) {
            memo[key] = null;
          }
          return memo;
        }, baseInverted);
      }
      AttributeMap6.invert = invert2;
      function transform2(a, b, priority = false) {
        if (typeof a !== "object") {
          return b;
        }
        if (typeof b !== "object") {
          return void 0;
        }
        if (!priority) {
          return b;
        }
        const attributes = Object.keys(b).reduce((attrs, key) => {
          if (a[key] === void 0) {
            attrs[key] = b[key];
          }
          return attrs;
        }, {});
        return Object.keys(attributes).length > 0 ? attributes : void 0;
      }
      AttributeMap6.transform = transform2;
    })(AttributeMap5 || (AttributeMap5 = {}));
    exports2.default = AttributeMap5;
  }
});

// node_modules/quill-delta/dist/Op.js
var require_Op = __commonJS({
  "node_modules/quill-delta/dist/Op.js"(exports2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", {
      value: true
    });
    var Op4;
    (function(Op5) {
      function length(op) {
        if (typeof op.delete === "number") {
          return op.delete;
        } else if (typeof op.retain === "number") {
          return op.retain;
        } else if (typeof op.retain === "object" && op.retain !== null) {
          return 1;
        } else {
          return typeof op.insert === "string" ? op.insert.length : 1;
        }
      }
      Op5.length = length;
    })(Op4 || (Op4 = {}));
    exports2.default = Op4;
  }
});

// node_modules/quill-delta/dist/OpIterator.js
var require_OpIterator = __commonJS({
  "node_modules/quill-delta/dist/OpIterator.js"(exports2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", {
      value: true
    });
    var Op_1 = require_Op();
    var Iterator = class {
      constructor(ops) {
        this.ops = ops;
        this.index = 0;
        this.offset = 0;
      }
      hasNext() {
        return this.peekLength() < Infinity;
      }
      next(length) {
        if (!length) {
          length = Infinity;
        }
        const nextOp = this.ops[this.index];
        if (nextOp) {
          const offset = this.offset;
          const opLength = Op_1.default.length(nextOp);
          if (length >= opLength - offset) {
            length = opLength - offset;
            this.index += 1;
            this.offset = 0;
          } else {
            this.offset += length;
          }
          if (typeof nextOp.delete === "number") {
            return {
              delete: length
            };
          } else {
            const retOp = {};
            if (nextOp.attributes) {
              retOp.attributes = nextOp.attributes;
            }
            if (typeof nextOp.retain === "number") {
              retOp.retain = length;
            } else if (typeof nextOp.retain === "object" && nextOp.retain !== null) {
              retOp.retain = nextOp.retain;
            } else if (typeof nextOp.insert === "string") {
              retOp.insert = nextOp.insert.substr(offset, length);
            } else {
              retOp.insert = nextOp.insert;
            }
            return retOp;
          }
        } else {
          return {
            retain: Infinity
          };
        }
      }
      peek() {
        return this.ops[this.index];
      }
      peekLength() {
        if (this.ops[this.index]) {
          return Op_1.default.length(this.ops[this.index]) - this.offset;
        } else {
          return Infinity;
        }
      }
      peekType() {
        const op = this.ops[this.index];
        if (op) {
          if (typeof op.delete === "number") {
            return "delete";
          } else if (typeof op.retain === "number" || typeof op.retain === "object" && op.retain !== null) {
            return "retain";
          } else {
            return "insert";
          }
        }
        return "retain";
      }
      rest() {
        if (!this.hasNext()) {
          return [];
        } else if (this.offset === 0) {
          return this.ops.slice(this.index);
        } else {
          const offset = this.offset;
          const index = this.index;
          const next = this.next();
          const rest2 = this.ops.slice(this.index);
          this.offset = offset;
          this.index = index;
          return [next].concat(rest2);
        }
      }
    };
    exports2.default = Iterator;
  }
});

// node_modules/quill-delta/dist/Delta.js
var require_Delta = __commonJS({
  "node_modules/quill-delta/dist/Delta.js"(exports2, module2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", {
      value: true
    });
    exports2.AttributeMap = exports2.OpIterator = exports2.Op = void 0;
    var diff = require_diff();
    var cloneDeep2 = require_lodash();
    var isEqual3 = require_lodash2();
    var AttributeMap_1 = require_AttributeMap();
    exports2.AttributeMap = AttributeMap_1.default;
    var Op_1 = require_Op();
    exports2.Op = Op_1.default;
    var OpIterator_1 = require_OpIterator();
    exports2.OpIterator = OpIterator_1.default;
    var NULL_CHARACTER = String.fromCharCode(0);
    var getEmbedTypeAndData = (a, b) => {
      if (typeof a !== "object" || a === null) {
        throw new Error(`cannot retain a ${typeof a}`);
      }
      if (typeof b !== "object" || b === null) {
        throw new Error(`cannot retain a ${typeof b}`);
      }
      const embedType = Object.keys(a)[0];
      if (!embedType || embedType !== Object.keys(b)[0]) {
        throw new Error(`embed types not matched: ${embedType} != ${Object.keys(b)[0]}`);
      }
      return [embedType, a[embedType], b[embedType]];
    };
    var Delta13 = class _Delta {
      constructor(ops) {
        if (Array.isArray(ops)) {
          this.ops = ops;
        } else if (ops != null && Array.isArray(ops.ops)) {
          this.ops = ops.ops;
        } else {
          this.ops = [];
        }
      }
      static registerEmbed(embedType, handler) {
        this.handlers[embedType] = handler;
      }
      static unregisterEmbed(embedType) {
        delete this.handlers[embedType];
      }
      static getHandler(embedType) {
        const handler = this.handlers[embedType];
        if (!handler) {
          throw new Error(`no handlers for embed type "${embedType}"`);
        }
        return handler;
      }
      insert(arg, attributes) {
        const newOp = {};
        if (typeof arg === "string" && arg.length === 0) {
          return this;
        }
        newOp.insert = arg;
        if (attributes != null && typeof attributes === "object" && Object.keys(attributes).length > 0) {
          newOp.attributes = attributes;
        }
        return this.push(newOp);
      }
      delete(length) {
        if (length <= 0) {
          return this;
        }
        return this.push({
          delete: length
        });
      }
      retain(length, attributes) {
        if (typeof length === "number" && length <= 0) {
          return this;
        }
        const newOp = {
          retain: length
        };
        if (attributes != null && typeof attributes === "object" && Object.keys(attributes).length > 0) {
          newOp.attributes = attributes;
        }
        return this.push(newOp);
      }
      push(newOp) {
        let index = this.ops.length;
        let lastOp = this.ops[index - 1];
        newOp = cloneDeep2(newOp);
        if (typeof lastOp === "object") {
          if (typeof newOp.delete === "number" && typeof lastOp.delete === "number") {
            this.ops[index - 1] = {
              delete: lastOp.delete + newOp.delete
            };
            return this;
          }
          if (typeof lastOp.delete === "number" && newOp.insert != null) {
            index -= 1;
            lastOp = this.ops[index - 1];
            if (typeof lastOp !== "object") {
              this.ops.unshift(newOp);
              return this;
            }
          }
          if (isEqual3(newOp.attributes, lastOp.attributes)) {
            if (typeof newOp.insert === "string" && typeof lastOp.insert === "string") {
              this.ops[index - 1] = {
                insert: lastOp.insert + newOp.insert
              };
              if (typeof newOp.attributes === "object") {
                this.ops[index - 1].attributes = newOp.attributes;
              }
              return this;
            } else if (typeof newOp.retain === "number" && typeof lastOp.retain === "number") {
              this.ops[index - 1] = {
                retain: lastOp.retain + newOp.retain
              };
              if (typeof newOp.attributes === "object") {
                this.ops[index - 1].attributes = newOp.attributes;
              }
              return this;
            }
          }
        }
        if (index === this.ops.length) {
          this.ops.push(newOp);
        } else {
          this.ops.splice(index, 0, newOp);
        }
        return this;
      }
      chop() {
        const lastOp = this.ops[this.ops.length - 1];
        if (lastOp && typeof lastOp.retain === "number" && !lastOp.attributes) {
          this.ops.pop();
        }
        return this;
      }
      filter(predicate) {
        return this.ops.filter(predicate);
      }
      forEach(predicate) {
        this.ops.forEach(predicate);
      }
      map(predicate) {
        return this.ops.map(predicate);
      }
      partition(predicate) {
        const passed = [];
        const failed = [];
        this.forEach((op) => {
          const target = predicate(op) ? passed : failed;
          target.push(op);
        });
        return [passed, failed];
      }
      reduce(predicate, initialValue) {
        return this.ops.reduce(predicate, initialValue);
      }
      changeLength() {
        return this.reduce((length, elem) => {
          if (elem.insert) {
            return length + Op_1.default.length(elem);
          } else if (elem.delete) {
            return length - elem.delete;
          }
          return length;
        }, 0);
      }
      length() {
        return this.reduce((length, elem) => {
          return length + Op_1.default.length(elem);
        }, 0);
      }
      slice(start = 0, end = Infinity) {
        const ops = [];
        const iter = new OpIterator_1.default(this.ops);
        let index = 0;
        while (index < end && iter.hasNext()) {
          let nextOp;
          if (index < start) {
            nextOp = iter.next(start - index);
          } else {
            nextOp = iter.next(end - index);
            ops.push(nextOp);
          }
          index += Op_1.default.length(nextOp);
        }
        return new _Delta(ops);
      }
      compose(other) {
        const thisIter = new OpIterator_1.default(this.ops);
        const otherIter = new OpIterator_1.default(other.ops);
        const ops = [];
        const firstOther = otherIter.peek();
        if (firstOther != null && typeof firstOther.retain === "number" && firstOther.attributes == null) {
          let firstLeft = firstOther.retain;
          while (thisIter.peekType() === "insert" && thisIter.peekLength() <= firstLeft) {
            firstLeft -= thisIter.peekLength();
            ops.push(thisIter.next());
          }
          if (firstOther.retain - firstLeft > 0) {
            otherIter.next(firstOther.retain - firstLeft);
          }
        }
        const delta = new _Delta(ops);
        while (thisIter.hasNext() || otherIter.hasNext()) {
          if (otherIter.peekType() === "insert") {
            delta.push(otherIter.next());
          } else if (thisIter.peekType() === "delete") {
            delta.push(thisIter.next());
          } else {
            const length = Math.min(thisIter.peekLength(), otherIter.peekLength());
            const thisOp = thisIter.next(length);
            const otherOp = otherIter.next(length);
            if (otherOp.retain) {
              const newOp = {};
              if (typeof thisOp.retain === "number") {
                newOp.retain = typeof otherOp.retain === "number" ? length : otherOp.retain;
              } else {
                if (typeof otherOp.retain === "number") {
                  if (thisOp.retain == null) {
                    newOp.insert = thisOp.insert;
                  } else {
                    newOp.retain = thisOp.retain;
                  }
                } else {
                  const action = thisOp.retain == null ? "insert" : "retain";
                  const [embedType, thisData, otherData] = getEmbedTypeAndData(thisOp[action], otherOp.retain);
                  const handler = _Delta.getHandler(embedType);
                  newOp[action] = {
                    [embedType]: handler.compose(thisData, otherData, action === "retain")
                  };
                }
              }
              const attributes = AttributeMap_1.default.compose(thisOp.attributes, otherOp.attributes, typeof thisOp.retain === "number");
              if (attributes) {
                newOp.attributes = attributes;
              }
              delta.push(newOp);
              if (!otherIter.hasNext() && isEqual3(delta.ops[delta.ops.length - 1], newOp)) {
                const rest2 = new _Delta(thisIter.rest());
                return delta.concat(rest2).chop();
              }
            } else if (typeof otherOp.delete === "number" && (typeof thisOp.retain === "number" || typeof thisOp.retain === "object" && thisOp.retain !== null)) {
              delta.push(otherOp);
            }
          }
        }
        return delta.chop();
      }
      concat(other) {
        const delta = new _Delta(this.ops.slice());
        if (other.ops.length > 0) {
          delta.push(other.ops[0]);
          delta.ops = delta.ops.concat(other.ops.slice(1));
        }
        return delta;
      }
      diff(other, cursor) {
        if (this.ops === other.ops) {
          return new _Delta();
        }
        const strings = [this, other].map((delta) => {
          return delta.map((op) => {
            if (op.insert != null) {
              return typeof op.insert === "string" ? op.insert : NULL_CHARACTER;
            }
            const prep = delta === other ? "on" : "with";
            throw new Error("diff() called " + prep + " non-document");
          }).join("");
        });
        const retDelta = new _Delta();
        const diffResult = diff(strings[0], strings[1], cursor, true);
        const thisIter = new OpIterator_1.default(this.ops);
        const otherIter = new OpIterator_1.default(other.ops);
        diffResult.forEach((component) => {
          let length = component[1].length;
          while (length > 0) {
            let opLength = 0;
            switch (component[0]) {
              case diff.INSERT:
                opLength = Math.min(otherIter.peekLength(), length);
                retDelta.push(otherIter.next(opLength));
                break;
              case diff.DELETE:
                opLength = Math.min(length, thisIter.peekLength());
                thisIter.next(opLength);
                retDelta.delete(opLength);
                break;
              case diff.EQUAL:
                opLength = Math.min(thisIter.peekLength(), otherIter.peekLength(), length);
                const thisOp = thisIter.next(opLength);
                const otherOp = otherIter.next(opLength);
                if (isEqual3(thisOp.insert, otherOp.insert)) {
                  retDelta.retain(opLength, AttributeMap_1.default.diff(thisOp.attributes, otherOp.attributes));
                } else {
                  retDelta.push(otherOp).delete(opLength);
                }
                break;
            }
            length -= opLength;
          }
        });
        return retDelta.chop();
      }
      eachLine(predicate, newline = "\n") {
        const iter = new OpIterator_1.default(this.ops);
        let line = new _Delta();
        let i = 0;
        while (iter.hasNext()) {
          if (iter.peekType() !== "insert") {
            return;
          }
          const thisOp = iter.peek();
          const start = Op_1.default.length(thisOp) - iter.peekLength();
          const index = typeof thisOp.insert === "string" ? thisOp.insert.indexOf(newline, start) - start : -1;
          if (index < 0) {
            line.push(iter.next());
          } else if (index > 0) {
            line.push(iter.next(index));
          } else {
            if (predicate(line, iter.next(1).attributes || {}, i) === false) {
              return;
            }
            i += 1;
            line = new _Delta();
          }
        }
        if (line.length() > 0) {
          predicate(line, {}, i);
        }
      }
      invert(base) {
        const inverted = new _Delta();
        this.reduce((baseIndex, op) => {
          if (op.insert) {
            inverted.delete(Op_1.default.length(op));
          } else if (typeof op.retain === "number" && op.attributes == null) {
            inverted.retain(op.retain);
            return baseIndex + op.retain;
          } else if (op.delete || typeof op.retain === "number") {
            const length = op.delete || op.retain;
            const slice2 = base.slice(baseIndex, baseIndex + length);
            slice2.forEach((baseOp) => {
              if (op.delete) {
                inverted.push(baseOp);
              } else if (op.retain && op.attributes) {
                inverted.retain(Op_1.default.length(baseOp), AttributeMap_1.default.invert(op.attributes, baseOp.attributes));
              }
            });
            return baseIndex + length;
          } else if (typeof op.retain === "object" && op.retain !== null) {
            const slice2 = base.slice(baseIndex, baseIndex + 1);
            const baseOp = new OpIterator_1.default(slice2.ops).next();
            const [embedType, opData, baseOpData] = getEmbedTypeAndData(op.retain, baseOp.insert);
            const handler = _Delta.getHandler(embedType);
            inverted.retain({
              [embedType]: handler.invert(opData, baseOpData)
            }, AttributeMap_1.default.invert(op.attributes, baseOp.attributes));
            return baseIndex + 1;
          }
          return baseIndex;
        }, 0);
        return inverted.chop();
      }
      transform(arg, priority = false) {
        priority = !!priority;
        if (typeof arg === "number") {
          return this.transformPosition(arg, priority);
        }
        const other = arg;
        const thisIter = new OpIterator_1.default(this.ops);
        const otherIter = new OpIterator_1.default(other.ops);
        const delta = new _Delta();
        while (thisIter.hasNext() || otherIter.hasNext()) {
          if (thisIter.peekType() === "insert" && (priority || otherIter.peekType() !== "insert")) {
            delta.retain(Op_1.default.length(thisIter.next()));
          } else if (otherIter.peekType() === "insert") {
            delta.push(otherIter.next());
          } else {
            const length = Math.min(thisIter.peekLength(), otherIter.peekLength());
            const thisOp = thisIter.next(length);
            const otherOp = otherIter.next(length);
            if (thisOp.delete) {
              continue;
            } else if (otherOp.delete) {
              delta.push(otherOp);
            } else {
              const thisData = thisOp.retain;
              const otherData = otherOp.retain;
              let transformedData = typeof otherData === "object" && otherData !== null ? otherData : length;
              if (typeof thisData === "object" && thisData !== null && typeof otherData === "object" && otherData !== null) {
                const embedType = Object.keys(thisData)[0];
                if (embedType === Object.keys(otherData)[0]) {
                  const handler = _Delta.getHandler(embedType);
                  if (handler) {
                    transformedData = {
                      [embedType]: handler.transform(thisData[embedType], otherData[embedType], priority)
                    };
                  }
                }
              }
              delta.retain(transformedData, AttributeMap_1.default.transform(thisOp.attributes, otherOp.attributes, priority));
            }
          }
        }
        return delta.chop();
      }
      transformPosition(index, priority = false) {
        priority = !!priority;
        const thisIter = new OpIterator_1.default(this.ops);
        let offset = 0;
        while (thisIter.hasNext() && offset <= index) {
          const length = thisIter.peekLength();
          const nextType = thisIter.peekType();
          thisIter.next();
          if (nextType === "delete") {
            index -= Math.min(length, index - offset);
            continue;
          } else if (nextType === "insert" && (offset < index || !priority)) {
            index += length;
          }
          offset += length;
        }
        return index;
      }
    };
    Delta13.Op = Op_1.default;
    Delta13.OpIterator = OpIterator_1.default;
    Delta13.AttributeMap = AttributeMap_1.default;
    Delta13.handlers = {};
    exports2.default = Delta13;
    if (typeof module2 === "object") {
      module2.exports = Delta13;
      module2.exports.default = Delta13;
    }
  }
});

// node_modules/quill/node_modules/eventemitter3/index.js
var require_eventemitter3 = __commonJS({
  "node_modules/quill/node_modules/eventemitter3/index.js"(exports2, module2) {
    "use strict";
    var has2 = Object.prototype.hasOwnProperty;
    var prefix = "~";
    function Events() {
    }
    if (Object.create) {
      Events.prototype = /* @__PURE__ */ Object.create(null);
      if (!new Events().__proto__) prefix = false;
    }
    function EE(fn, context, once2) {
      this.fn = fn;
      this.context = context;
      this.once = once2 || false;
    }
    function addListener(emitter, event, fn, context, once2) {
      if (typeof fn !== "function") {
        throw new TypeError("The listener must be a function");
      }
      var listener = new EE(fn, context || emitter, once2), evt = prefix ? prefix + event : event;
      if (!emitter._events[evt]) emitter._events[evt] = listener, emitter._eventsCount++;
      else if (!emitter._events[evt].fn) emitter._events[evt].push(listener);
      else emitter._events[evt] = [emitter._events[evt], listener];
      return emitter;
    }
    function clearEvent(emitter, evt) {
      if (--emitter._eventsCount === 0) emitter._events = new Events();
      else delete emitter._events[evt];
    }
    function EventEmitter2() {
      this._events = new Events();
      this._eventsCount = 0;
    }
    EventEmitter2.prototype.eventNames = function eventNames() {
      var names = [], events, name;
      if (this._eventsCount === 0) return names;
      for (name in events = this._events) {
        if (has2.call(events, name)) names.push(prefix ? name.slice(1) : name);
      }
      if (Object.getOwnPropertySymbols) {
        return names.concat(Object.getOwnPropertySymbols(events));
      }
      return names;
    };
    EventEmitter2.prototype.listeners = function listeners(event) {
      var evt = prefix ? prefix + event : event, handlers = this._events[evt];
      if (!handlers) return [];
      if (handlers.fn) return [handlers.fn];
      for (var i = 0, l = handlers.length, ee = new Array(l); i < l; i++) {
        ee[i] = handlers[i].fn;
      }
      return ee;
    };
    EventEmitter2.prototype.listenerCount = function listenerCount(event) {
      var evt = prefix ? prefix + event : event, listeners = this._events[evt];
      if (!listeners) return 0;
      if (listeners.fn) return 1;
      return listeners.length;
    };
    EventEmitter2.prototype.emit = function emit(event, a1, a2, a3, a4, a5) {
      var evt = prefix ? prefix + event : event;
      if (!this._events[evt]) return false;
      var listeners = this._events[evt], len = arguments.length, args, i;
      if (listeners.fn) {
        if (listeners.once) this.removeListener(event, listeners.fn, void 0, true);
        switch (len) {
          case 1:
            return listeners.fn.call(listeners.context), true;
          case 2:
            return listeners.fn.call(listeners.context, a1), true;
          case 3:
            return listeners.fn.call(listeners.context, a1, a2), true;
          case 4:
            return listeners.fn.call(listeners.context, a1, a2, a3), true;
          case 5:
            return listeners.fn.call(listeners.context, a1, a2, a3, a4), true;
          case 6:
            return listeners.fn.call(listeners.context, a1, a2, a3, a4, a5), true;
        }
        for (i = 1, args = new Array(len - 1); i < len; i++) {
          args[i - 1] = arguments[i];
        }
        listeners.fn.apply(listeners.context, args);
      } else {
        var length = listeners.length, j;
        for (i = 0; i < length; i++) {
          if (listeners[i].once) this.removeListener(event, listeners[i].fn, void 0, true);
          switch (len) {
            case 1:
              listeners[i].fn.call(listeners[i].context);
              break;
            case 2:
              listeners[i].fn.call(listeners[i].context, a1);
              break;
            case 3:
              listeners[i].fn.call(listeners[i].context, a1, a2);
              break;
            case 4:
              listeners[i].fn.call(listeners[i].context, a1, a2, a3);
              break;
            default:
              if (!args) for (j = 1, args = new Array(len - 1); j < len; j++) {
                args[j - 1] = arguments[j];
              }
              listeners[i].fn.apply(listeners[i].context, args);
          }
        }
      }
      return true;
    };
    EventEmitter2.prototype.on = function on(event, fn, context) {
      return addListener(this, event, fn, context, false);
    };
    EventEmitter2.prototype.once = function once2(event, fn, context) {
      return addListener(this, event, fn, context, true);
    };
    EventEmitter2.prototype.removeListener = function removeListener(event, fn, context, once2) {
      var evt = prefix ? prefix + event : event;
      if (!this._events[evt]) return this;
      if (!fn) {
        clearEvent(this, evt);
        return this;
      }
      var listeners = this._events[evt];
      if (listeners.fn) {
        if (listeners.fn === fn && (!once2 || listeners.once) && (!context || listeners.context === context)) {
          clearEvent(this, evt);
        }
      } else {
        for (var i = 0, events = [], length = listeners.length; i < length; i++) {
          if (listeners[i].fn !== fn || once2 && !listeners[i].once || context && listeners[i].context !== context) {
            events.push(listeners[i]);
          }
        }
        if (events.length) this._events[evt] = events.length === 1 ? events[0] : events;
        else clearEvent(this, evt);
      }
      return this;
    };
    EventEmitter2.prototype.removeAllListeners = function removeAllListeners(event) {
      var evt;
      if (event) {
        evt = prefix ? prefix + event : event;
        if (this._events[evt]) clearEvent(this, evt);
      } else {
        this._events = new Events();
        this._eventsCount = 0;
      }
      return this;
    };
    EventEmitter2.prototype.off = EventEmitter2.prototype.removeListener;
    EventEmitter2.prototype.addListener = EventEmitter2.prototype.on;
    EventEmitter2.prefixed = prefix;
    EventEmitter2.EventEmitter = EventEmitter2;
    if ("undefined" !== typeof module2) {
      module2.exports = EventEmitter2;
    }
  }
});

// node_modules/lodash-es/_freeGlobal.js
var freeGlobal = typeof global == "object" && global && global.Object === Object && global;
var freeGlobal_default = freeGlobal;

// node_modules/lodash-es/_root.js
var freeSelf = typeof self == "object" && self && self.Object === Object && self;
var root = freeGlobal_default || freeSelf || Function("return this")();
var root_default = root;

// node_modules/lodash-es/_Symbol.js
var Symbol = root_default.Symbol;
var Symbol_default = Symbol;

// node_modules/lodash-es/_getRawTag.js
var objectProto = Object.prototype;
var hasOwnProperty = objectProto.hasOwnProperty;
var nativeObjectToString = objectProto.toString;
var symToStringTag = Symbol_default ? Symbol_default.toStringTag : void 0;
function getRawTag(value) {
  var isOwn = hasOwnProperty.call(value, symToStringTag), tag = value[symToStringTag];
  try {
    value[symToStringTag] = void 0;
    var unmasked = true;
  } catch (e) {
  }
  var result2 = nativeObjectToString.call(value);
  if (unmasked) {
    if (isOwn) {
      value[symToStringTag] = tag;
    } else {
      delete value[symToStringTag];
    }
  }
  return result2;
}
var getRawTag_default = getRawTag;

// node_modules/lodash-es/_objectToString.js
var objectProto2 = Object.prototype;
var nativeObjectToString2 = objectProto2.toString;
function objectToString(value) {
  return nativeObjectToString2.call(value);
}
var objectToString_default = objectToString;

// node_modules/lodash-es/_baseGetTag.js
var nullTag = "[object Null]";
var undefinedTag = "[object Undefined]";
var symToStringTag2 = Symbol_default ? Symbol_default.toStringTag : void 0;
function baseGetTag(value) {
  if (value == null) {
    return value === void 0 ? undefinedTag : nullTag;
  }
  return symToStringTag2 && symToStringTag2 in Object(value) ? getRawTag_default(value) : objectToString_default(value);
}
var baseGetTag_default = baseGetTag;

// node_modules/lodash-es/isObjectLike.js
function isObjectLike(value) {
  return value != null && typeof value == "object";
}
var isObjectLike_default = isObjectLike;

// node_modules/lodash-es/isSymbol.js
var symbolTag = "[object Symbol]";
function isSymbol(value) {
  return typeof value == "symbol" || isObjectLike_default(value) && baseGetTag_default(value) == symbolTag;
}
var isSymbol_default = isSymbol;

// node_modules/lodash-es/_baseToNumber.js
var NAN = 0 / 0;
function baseToNumber(value) {
  if (typeof value == "number") {
    return value;
  }
  if (isSymbol_default(value)) {
    return NAN;
  }
  return +value;
}
var baseToNumber_default = baseToNumber;

// node_modules/lodash-es/_arrayMap.js
function arrayMap(array, iteratee2) {
  var index = -1, length = array == null ? 0 : array.length, result2 = Array(length);
  while (++index < length) {
    result2[index] = iteratee2(array[index], index, array);
  }
  return result2;
}
var arrayMap_default = arrayMap;

// node_modules/lodash-es/isArray.js
var isArray = Array.isArray;
var isArray_default = isArray;

// node_modules/lodash-es/_baseToString.js
var INFINITY = 1 / 0;
var symbolProto = Symbol_default ? Symbol_default.prototype : void 0;
var symbolToString = symbolProto ? symbolProto.toString : void 0;
function baseToString(value) {
  if (typeof value == "string") {
    return value;
  }
  if (isArray_default(value)) {
    return arrayMap_default(value, baseToString) + "";
  }
  if (isSymbol_default(value)) {
    return symbolToString ? symbolToString.call(value) : "";
  }
  var result2 = value + "";
  return result2 == "0" && 1 / value == -INFINITY ? "-0" : result2;
}
var baseToString_default = baseToString;

// node_modules/lodash-es/_createMathOperation.js
function createMathOperation(operator, defaultValue) {
  return function(value, other) {
    var result2;
    if (value === void 0 && other === void 0) {
      return defaultValue;
    }
    if (value !== void 0) {
      result2 = value;
    }
    if (other !== void 0) {
      if (result2 === void 0) {
        return other;
      }
      if (typeof value == "string" || typeof other == "string") {
        value = baseToString_default(value);
        other = baseToString_default(other);
      } else {
        value = baseToNumber_default(value);
        other = baseToNumber_default(other);
      }
      result2 = operator(value, other);
    }
    return result2;
  };
}
var createMathOperation_default = createMathOperation;

// node_modules/lodash-es/add.js
var add = createMathOperation_default(function(augend, addend) {
  return augend + addend;
}, 0);
var add_default = add;

// node_modules/lodash-es/_trimmedEndIndex.js
var reWhitespace = /\s/;
function trimmedEndIndex(string) {
  var index = string.length;
  while (index-- && reWhitespace.test(string.charAt(index))) {
  }
  return index;
}
var trimmedEndIndex_default = trimmedEndIndex;

// node_modules/lodash-es/_baseTrim.js
var reTrimStart = /^\s+/;
function baseTrim(string) {
  return string ? string.slice(0, trimmedEndIndex_default(string) + 1).replace(reTrimStart, "") : string;
}
var baseTrim_default = baseTrim;

// node_modules/lodash-es/isObject.js
function isObject(value) {
  var type = typeof value;
  return value != null && (type == "object" || type == "function");
}
var isObject_default = isObject;

// node_modules/lodash-es/toNumber.js
var NAN2 = 0 / 0;
var reIsBadHex = /^[-+]0x[0-9a-f]+$/i;
var reIsBinary = /^0b[01]+$/i;
var reIsOctal = /^0o[0-7]+$/i;
var freeParseInt = parseInt;
function toNumber(value) {
  if (typeof value == "number") {
    return value;
  }
  if (isSymbol_default(value)) {
    return NAN2;
  }
  if (isObject_default(value)) {
    var other = typeof value.valueOf == "function" ? value.valueOf() : value;
    value = isObject_default(other) ? other + "" : other;
  }
  if (typeof value != "string") {
    return value === 0 ? value : +value;
  }
  value = baseTrim_default(value);
  var isBinary = reIsBinary.test(value);
  return isBinary || reIsOctal.test(value) ? freeParseInt(value.slice(2), isBinary ? 2 : 8) : reIsBadHex.test(value) ? NAN2 : +value;
}
var toNumber_default = toNumber;

// node_modules/lodash-es/toFinite.js
var INFINITY2 = 1 / 0;
var MAX_INTEGER = 17976931348623157e292;
function toFinite(value) {
  if (!value) {
    return value === 0 ? value : 0;
  }
  value = toNumber_default(value);
  if (value === INFINITY2 || value === -INFINITY2) {
    var sign = value < 0 ? -1 : 1;
    return sign * MAX_INTEGER;
  }
  return value === value ? value : 0;
}
var toFinite_default = toFinite;

// node_modules/lodash-es/toInteger.js
function toInteger(value) {
  var result2 = toFinite_default(value), remainder = result2 % 1;
  return result2 === result2 ? remainder ? result2 - remainder : result2 : 0;
}
var toInteger_default = toInteger;

// node_modules/lodash-es/after.js
var FUNC_ERROR_TEXT = "Expected a function";
function after(n, func) {
  if (typeof func != "function") {
    throw new TypeError(FUNC_ERROR_TEXT);
  }
  n = toInteger_default(n);
  return function() {
    if (--n < 1) {
      return func.apply(this, arguments);
    }
  };
}
var after_default = after;

// node_modules/lodash-es/identity.js
function identity(value) {
  return value;
}
var identity_default = identity;

// node_modules/lodash-es/isFunction.js
var asyncTag = "[object AsyncFunction]";
var funcTag = "[object Function]";
var genTag = "[object GeneratorFunction]";
var proxyTag = "[object Proxy]";
function isFunction(value) {
  if (!isObject_default(value)) {
    return false;
  }
  var tag = baseGetTag_default(value);
  return tag == funcTag || tag == genTag || tag == asyncTag || tag == proxyTag;
}
var isFunction_default = isFunction;

// node_modules/lodash-es/_coreJsData.js
var coreJsData = root_default["__core-js_shared__"];
var coreJsData_default = coreJsData;

// node_modules/lodash-es/_isMasked.js
var maskSrcKey = function() {
  var uid = /[^.]+$/.exec(coreJsData_default && coreJsData_default.keys && coreJsData_default.keys.IE_PROTO || "");
  return uid ? "Symbol(src)_1." + uid : "";
}();
function isMasked(func) {
  return !!maskSrcKey && maskSrcKey in func;
}
var isMasked_default = isMasked;

// node_modules/lodash-es/_toSource.js
var funcProto = Function.prototype;
var funcToString = funcProto.toString;
function toSource(func) {
  if (func != null) {
    try {
      return funcToString.call(func);
    } catch (e) {
    }
    try {
      return func + "";
    } catch (e) {
    }
  }
  return "";
}
var toSource_default = toSource;

// node_modules/lodash-es/_baseIsNative.js
var reRegExpChar = /[\\^$.*+?()[\]{}|]/g;
var reIsHostCtor = /^\[object .+?Constructor\]$/;
var funcProto2 = Function.prototype;
var objectProto3 = Object.prototype;
var funcToString2 = funcProto2.toString;
var hasOwnProperty2 = objectProto3.hasOwnProperty;
var reIsNative = RegExp("^" + funcToString2.call(hasOwnProperty2).replace(reRegExpChar, "\\$&").replace(/hasOwnProperty|(function).*?(?=\\\()| for .+?(?=\\\])/g, "$1.*?") + "$");
function baseIsNative(value) {
  if (!isObject_default(value) || isMasked_default(value)) {
    return false;
  }
  var pattern = isFunction_default(value) ? reIsNative : reIsHostCtor;
  return pattern.test(toSource_default(value));
}
var baseIsNative_default = baseIsNative;

// node_modules/lodash-es/_getValue.js
function getValue(object, key) {
  return object == null ? void 0 : object[key];
}
var getValue_default = getValue;

// node_modules/lodash-es/_getNative.js
function getNative(object, key) {
  var value = getValue_default(object, key);
  return baseIsNative_default(value) ? value : void 0;
}
var getNative_default = getNative;

// node_modules/lodash-es/_WeakMap.js
var WeakMap2 = getNative_default(root_default, "WeakMap");
var WeakMap_default = WeakMap2;

// node_modules/lodash-es/_metaMap.js
var metaMap = WeakMap_default && new WeakMap_default();
var metaMap_default = metaMap;

// node_modules/lodash-es/_baseSetData.js
var baseSetData = !metaMap_default ? identity_default : function(func, data) {
  metaMap_default.set(func, data);
  return func;
};
var baseSetData_default = baseSetData;

// node_modules/lodash-es/_baseCreate.js
var objectCreate = Object.create;
var baseCreate = /* @__PURE__ */ function() {
  function object() {
  }
  return function(proto) {
    if (!isObject_default(proto)) {
      return {};
    }
    if (objectCreate) {
      return objectCreate(proto);
    }
    object.prototype = proto;
    var result2 = new object();
    object.prototype = void 0;
    return result2;
  };
}();
var baseCreate_default = baseCreate;

// node_modules/lodash-es/_createCtor.js
function createCtor(Ctor) {
  return function() {
    var args = arguments;
    switch (args.length) {
      case 0:
        return new Ctor();
      case 1:
        return new Ctor(args[0]);
      case 2:
        return new Ctor(args[0], args[1]);
      case 3:
        return new Ctor(args[0], args[1], args[2]);
      case 4:
        return new Ctor(args[0], args[1], args[2], args[3]);
      case 5:
        return new Ctor(args[0], args[1], args[2], args[3], args[4]);
      case 6:
        return new Ctor(args[0], args[1], args[2], args[3], args[4], args[5]);
      case 7:
        return new Ctor(args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
    }
    var thisBinding = baseCreate_default(Ctor.prototype), result2 = Ctor.apply(thisBinding, args);
    return isObject_default(result2) ? result2 : thisBinding;
  };
}
var createCtor_default = createCtor;

// node_modules/lodash-es/_createBind.js
var WRAP_BIND_FLAG = 1;
function createBind(func, bitmask, thisArg) {
  var isBind = bitmask & WRAP_BIND_FLAG, Ctor = createCtor_default(func);
  function wrapper() {
    var fn = this && this !== root_default && this instanceof wrapper ? Ctor : func;
    return fn.apply(isBind ? thisArg : this, arguments);
  }
  return wrapper;
}
var createBind_default = createBind;

// node_modules/lodash-es/_apply.js
function apply(func, thisArg, args) {
  switch (args.length) {
    case 0:
      return func.call(thisArg);
    case 1:
      return func.call(thisArg, args[0]);
    case 2:
      return func.call(thisArg, args[0], args[1]);
    case 3:
      return func.call(thisArg, args[0], args[1], args[2]);
  }
  return func.apply(thisArg, args);
}
var apply_default = apply;

// node_modules/lodash-es/_composeArgs.js
var nativeMax = Math.max;
function composeArgs(args, partials, holders, isCurried) {
  var argsIndex = -1, argsLength = args.length, holdersLength = holders.length, leftIndex = -1, leftLength = partials.length, rangeLength = nativeMax(argsLength - holdersLength, 0), result2 = Array(leftLength + rangeLength), isUncurried = !isCurried;
  while (++leftIndex < leftLength) {
    result2[leftIndex] = partials[leftIndex];
  }
  while (++argsIndex < holdersLength) {
    if (isUncurried || argsIndex < argsLength) {
      result2[holders[argsIndex]] = args[argsIndex];
    }
  }
  while (rangeLength--) {
    result2[leftIndex++] = args[argsIndex++];
  }
  return result2;
}
var composeArgs_default = composeArgs;

// node_modules/lodash-es/_composeArgsRight.js
var nativeMax2 = Math.max;
function composeArgsRight(args, partials, holders, isCurried) {
  var argsIndex = -1, argsLength = args.length, holdersIndex = -1, holdersLength = holders.length, rightIndex = -1, rightLength = partials.length, rangeLength = nativeMax2(argsLength - holdersLength, 0), result2 = Array(rangeLength + rightLength), isUncurried = !isCurried;
  while (++argsIndex < rangeLength) {
    result2[argsIndex] = args[argsIndex];
  }
  var offset = argsIndex;
  while (++rightIndex < rightLength) {
    result2[offset + rightIndex] = partials[rightIndex];
  }
  while (++holdersIndex < holdersLength) {
    if (isUncurried || argsIndex < argsLength) {
      result2[offset + holders[holdersIndex]] = args[argsIndex++];
    }
  }
  return result2;
}
var composeArgsRight_default = composeArgsRight;

// node_modules/lodash-es/_countHolders.js
function countHolders(array, placeholder) {
  var length = array.length, result2 = 0;
  while (length--) {
    if (array[length] === placeholder) {
      ++result2;
    }
  }
  return result2;
}
var countHolders_default = countHolders;

// node_modules/lodash-es/_baseLodash.js
function baseLodash() {
}
var baseLodash_default = baseLodash;

// node_modules/lodash-es/_LazyWrapper.js
var MAX_ARRAY_LENGTH = 4294967295;
function LazyWrapper(value) {
  this.__wrapped__ = value;
  this.__actions__ = [];
  this.__dir__ = 1;
  this.__filtered__ = false;
  this.__iteratees__ = [];
  this.__takeCount__ = MAX_ARRAY_LENGTH;
  this.__views__ = [];
}
LazyWrapper.prototype = baseCreate_default(baseLodash_default.prototype);
LazyWrapper.prototype.constructor = LazyWrapper;
var LazyWrapper_default = LazyWrapper;

// node_modules/lodash-es/noop.js
function noop() {
}
var noop_default = noop;

// node_modules/lodash-es/_getData.js
var getData = !metaMap_default ? noop_default : function(func) {
  return metaMap_default.get(func);
};
var getData_default = getData;

// node_modules/lodash-es/_realNames.js
var realNames = {};
var realNames_default = realNames;

// node_modules/lodash-es/_getFuncName.js
var objectProto4 = Object.prototype;
var hasOwnProperty3 = objectProto4.hasOwnProperty;
function getFuncName(func) {
  var result2 = func.name + "", array = realNames_default[result2], length = hasOwnProperty3.call(realNames_default, result2) ? array.length : 0;
  while (length--) {
    var data = array[length], otherFunc = data.func;
    if (otherFunc == null || otherFunc == func) {
      return data.name;
    }
  }
  return result2;
}
var getFuncName_default = getFuncName;

// node_modules/lodash-es/_LodashWrapper.js
function LodashWrapper(value, chainAll) {
  this.__wrapped__ = value;
  this.__actions__ = [];
  this.__chain__ = !!chainAll;
  this.__index__ = 0;
  this.__values__ = void 0;
}
LodashWrapper.prototype = baseCreate_default(baseLodash_default.prototype);
LodashWrapper.prototype.constructor = LodashWrapper;
var LodashWrapper_default = LodashWrapper;

// node_modules/lodash-es/_copyArray.js
function copyArray(source, array) {
  var index = -1, length = source.length;
  array || (array = Array(length));
  while (++index < length) {
    array[index] = source[index];
  }
  return array;
}
var copyArray_default = copyArray;

// node_modules/lodash-es/_wrapperClone.js
function wrapperClone(wrapper) {
  if (wrapper instanceof LazyWrapper_default) {
    return wrapper.clone();
  }
  var result2 = new LodashWrapper_default(wrapper.__wrapped__, wrapper.__chain__);
  result2.__actions__ = copyArray_default(wrapper.__actions__);
  result2.__index__ = wrapper.__index__;
  result2.__values__ = wrapper.__values__;
  return result2;
}
var wrapperClone_default = wrapperClone;

// node_modules/lodash-es/wrapperLodash.js
var objectProto5 = Object.prototype;
var hasOwnProperty4 = objectProto5.hasOwnProperty;
function lodash(value) {
  if (isObjectLike_default(value) && !isArray_default(value) && !(value instanceof LazyWrapper_default)) {
    if (value instanceof LodashWrapper_default) {
      return value;
    }
    if (hasOwnProperty4.call(value, "__wrapped__")) {
      return wrapperClone_default(value);
    }
  }
  return new LodashWrapper_default(value);
}
lodash.prototype = baseLodash_default.prototype;
lodash.prototype.constructor = lodash;
var wrapperLodash_default = lodash;

// node_modules/lodash-es/_isLaziable.js
function isLaziable(func) {
  var funcName = getFuncName_default(func), other = wrapperLodash_default[funcName];
  if (typeof other != "function" || !(funcName in LazyWrapper_default.prototype)) {
    return false;
  }
  if (func === other) {
    return true;
  }
  var data = getData_default(other);
  return !!data && func === data[0];
}
var isLaziable_default = isLaziable;

// node_modules/lodash-es/_shortOut.js
var HOT_COUNT = 800;
var HOT_SPAN = 16;
var nativeNow = Date.now;
function shortOut(func) {
  var count = 0, lastCalled = 0;
  return function() {
    var stamp = nativeNow(), remaining = HOT_SPAN - (stamp - lastCalled);
    lastCalled = stamp;
    if (remaining > 0) {
      if (++count >= HOT_COUNT) {
        return arguments[0];
      }
    } else {
      count = 0;
    }
    return func.apply(void 0, arguments);
  };
}
var shortOut_default = shortOut;

// node_modules/lodash-es/_setData.js
var setData = shortOut_default(baseSetData_default);
var setData_default = setData;

// node_modules/lodash-es/_getWrapDetails.js
var reWrapDetails = /\{\n\/\* \[wrapped with (.+)\] \*/;
var reSplitDetails = /,? & /;
function getWrapDetails(source) {
  var match2 = source.match(reWrapDetails);
  return match2 ? match2[1].split(reSplitDetails) : [];
}
var getWrapDetails_default = getWrapDetails;

// node_modules/lodash-es/_insertWrapDetails.js
var reWrapComment = /\{(?:\n\/\* \[wrapped with .+\] \*\/)?\n?/;
function insertWrapDetails(source, details) {
  var length = details.length;
  if (!length) {
    return source;
  }
  var lastIndex = length - 1;
  details[lastIndex] = (length > 1 ? "& " : "") + details[lastIndex];
  details = details.join(length > 2 ? ", " : " ");
  return source.replace(reWrapComment, "{\n/* [wrapped with " + details + "] */\n");
}
var insertWrapDetails_default = insertWrapDetails;

// node_modules/lodash-es/constant.js
function constant(value) {
  return function() {
    return value;
  };
}
var constant_default = constant;

// node_modules/lodash-es/_defineProperty.js
var defineProperty = function() {
  try {
    var func = getNative_default(Object, "defineProperty");
    func({}, "", {});
    return func;
  } catch (e) {
  }
}();
var defineProperty_default = defineProperty;

// node_modules/lodash-es/_baseSetToString.js
var baseSetToString = !defineProperty_default ? identity_default : function(func, string) {
  return defineProperty_default(func, "toString", {
    "configurable": true,
    "enumerable": false,
    "value": constant_default(string),
    "writable": true
  });
};
var baseSetToString_default = baseSetToString;

// node_modules/lodash-es/_setToString.js
var setToString = shortOut_default(baseSetToString_default);
var setToString_default = setToString;

// node_modules/lodash-es/_arrayEach.js
function arrayEach(array, iteratee2) {
  var index = -1, length = array == null ? 0 : array.length;
  while (++index < length) {
    if (iteratee2(array[index], index, array) === false) {
      break;
    }
  }
  return array;
}
var arrayEach_default = arrayEach;

// node_modules/lodash-es/_baseFindIndex.js
function baseFindIndex(array, predicate, fromIndex, fromRight) {
  var length = array.length, index = fromIndex + (fromRight ? 1 : -1);
  while (fromRight ? index-- : ++index < length) {
    if (predicate(array[index], index, array)) {
      return index;
    }
  }
  return -1;
}
var baseFindIndex_default = baseFindIndex;

// node_modules/lodash-es/_baseIsNaN.js
function baseIsNaN(value) {
  return value !== value;
}
var baseIsNaN_default = baseIsNaN;

// node_modules/lodash-es/_strictIndexOf.js
function strictIndexOf(array, value, fromIndex) {
  var index = fromIndex - 1, length = array.length;
  while (++index < length) {
    if (array[index] === value) {
      return index;
    }
  }
  return -1;
}
var strictIndexOf_default = strictIndexOf;

// node_modules/lodash-es/_baseIndexOf.js
function baseIndexOf(array, value, fromIndex) {
  return value === value ? strictIndexOf_default(array, value, fromIndex) : baseFindIndex_default(array, baseIsNaN_default, fromIndex);
}
var baseIndexOf_default = baseIndexOf;

// node_modules/lodash-es/_arrayIncludes.js
function arrayIncludes(array, value) {
  var length = array == null ? 0 : array.length;
  return !!length && baseIndexOf_default(array, value, 0) > -1;
}
var arrayIncludes_default = arrayIncludes;

// node_modules/lodash-es/_updateWrapDetails.js
var WRAP_BIND_FLAG2 = 1;
var WRAP_BIND_KEY_FLAG = 2;
var WRAP_CURRY_FLAG = 8;
var WRAP_CURRY_RIGHT_FLAG = 16;
var WRAP_PARTIAL_FLAG = 32;
var WRAP_PARTIAL_RIGHT_FLAG = 64;
var WRAP_ARY_FLAG = 128;
var WRAP_REARG_FLAG = 256;
var WRAP_FLIP_FLAG = 512;
var wrapFlags = [["ary", WRAP_ARY_FLAG], ["bind", WRAP_BIND_FLAG2], ["bindKey", WRAP_BIND_KEY_FLAG], ["curry", WRAP_CURRY_FLAG], ["curryRight", WRAP_CURRY_RIGHT_FLAG], ["flip", WRAP_FLIP_FLAG], ["partial", WRAP_PARTIAL_FLAG], ["partialRight", WRAP_PARTIAL_RIGHT_FLAG], ["rearg", WRAP_REARG_FLAG]];
function updateWrapDetails(details, bitmask) {
  arrayEach_default(wrapFlags, function(pair) {
    var value = "_." + pair[0];
    if (bitmask & pair[1] && !arrayIncludes_default(details, value)) {
      details.push(value);
    }
  });
  return details.sort();
}
var updateWrapDetails_default = updateWrapDetails;

// node_modules/lodash-es/_setWrapToString.js
function setWrapToString(wrapper, reference, bitmask) {
  var source = reference + "";
  return setToString_default(wrapper, insertWrapDetails_default(source, updateWrapDetails_default(getWrapDetails_default(source), bitmask)));
}
var setWrapToString_default = setWrapToString;

// node_modules/lodash-es/_createRecurry.js
var WRAP_BIND_FLAG3 = 1;
var WRAP_BIND_KEY_FLAG2 = 2;
var WRAP_CURRY_BOUND_FLAG = 4;
var WRAP_CURRY_FLAG2 = 8;
var WRAP_PARTIAL_FLAG2 = 32;
var WRAP_PARTIAL_RIGHT_FLAG2 = 64;
function createRecurry(func, bitmask, wrapFunc, placeholder, thisArg, partials, holders, argPos, ary2, arity) {
  var isCurry = bitmask & WRAP_CURRY_FLAG2, newHolders = isCurry ? holders : void 0, newHoldersRight = isCurry ? void 0 : holders, newPartials = isCurry ? partials : void 0, newPartialsRight = isCurry ? void 0 : partials;
  bitmask |= isCurry ? WRAP_PARTIAL_FLAG2 : WRAP_PARTIAL_RIGHT_FLAG2;
  bitmask &= ~(isCurry ? WRAP_PARTIAL_RIGHT_FLAG2 : WRAP_PARTIAL_FLAG2);
  if (!(bitmask & WRAP_CURRY_BOUND_FLAG)) {
    bitmask &= ~(WRAP_BIND_FLAG3 | WRAP_BIND_KEY_FLAG2);
  }
  var newData = [func, bitmask, thisArg, newPartials, newHolders, newPartialsRight, newHoldersRight, argPos, ary2, arity];
  var result2 = wrapFunc.apply(void 0, newData);
  if (isLaziable_default(func)) {
    setData_default(result2, newData);
  }
  result2.placeholder = placeholder;
  return setWrapToString_default(result2, func, bitmask);
}
var createRecurry_default = createRecurry;

// node_modules/lodash-es/_getHolder.js
function getHolder(func) {
  var object = func;
  return object.placeholder;
}
var getHolder_default = getHolder;

// node_modules/lodash-es/_isIndex.js
var MAX_SAFE_INTEGER = 9007199254740991;
var reIsUint = /^(?:0|[1-9]\d*)$/;
function isIndex(value, length) {
  var type = typeof value;
  length = length == null ? MAX_SAFE_INTEGER : length;
  return !!length && (type == "number" || type != "symbol" && reIsUint.test(value)) && value > -1 && value % 1 == 0 && value < length;
}
var isIndex_default = isIndex;

// node_modules/lodash-es/_reorder.js
var nativeMin = Math.min;
function reorder(array, indexes) {
  var arrLength = array.length, length = nativeMin(indexes.length, arrLength), oldArray = copyArray_default(array);
  while (length--) {
    var index = indexes[length];
    array[length] = isIndex_default(index, arrLength) ? oldArray[index] : void 0;
  }
  return array;
}
var reorder_default = reorder;

// node_modules/lodash-es/_replaceHolders.js
var PLACEHOLDER = "__lodash_placeholder__";
function replaceHolders(array, placeholder) {
  var index = -1, length = array.length, resIndex = 0, result2 = [];
  while (++index < length) {
    var value = array[index];
    if (value === placeholder || value === PLACEHOLDER) {
      array[index] = PLACEHOLDER;
      result2[resIndex++] = index;
    }
  }
  return result2;
}
var replaceHolders_default = replaceHolders;

// node_modules/lodash-es/_createHybrid.js
var WRAP_BIND_FLAG4 = 1;
var WRAP_BIND_KEY_FLAG3 = 2;
var WRAP_CURRY_FLAG3 = 8;
var WRAP_CURRY_RIGHT_FLAG2 = 16;
var WRAP_ARY_FLAG2 = 128;
var WRAP_FLIP_FLAG2 = 512;
function createHybrid(func, bitmask, thisArg, partials, holders, partialsRight, holdersRight, argPos, ary2, arity) {
  var isAry = bitmask & WRAP_ARY_FLAG2, isBind = bitmask & WRAP_BIND_FLAG4, isBindKey = bitmask & WRAP_BIND_KEY_FLAG3, isCurried = bitmask & (WRAP_CURRY_FLAG3 | WRAP_CURRY_RIGHT_FLAG2), isFlip = bitmask & WRAP_FLIP_FLAG2, Ctor = isBindKey ? void 0 : createCtor_default(func);
  function wrapper() {
    var length = arguments.length, args = Array(length), index = length;
    while (index--) {
      args[index] = arguments[index];
    }
    if (isCurried) {
      var placeholder = getHolder_default(wrapper), holdersCount = countHolders_default(args, placeholder);
    }
    if (partials) {
      args = composeArgs_default(args, partials, holders, isCurried);
    }
    if (partialsRight) {
      args = composeArgsRight_default(args, partialsRight, holdersRight, isCurried);
    }
    length -= holdersCount;
    if (isCurried && length < arity) {
      var newHolders = replaceHolders_default(args, placeholder);
      return createRecurry_default(func, bitmask, createHybrid, wrapper.placeholder, thisArg, args, newHolders, argPos, ary2, arity - length);
    }
    var thisBinding = isBind ? thisArg : this, fn = isBindKey ? thisBinding[func] : func;
    length = args.length;
    if (argPos) {
      args = reorder_default(args, argPos);
    } else if (isFlip && length > 1) {
      args.reverse();
    }
    if (isAry && ary2 < length) {
      args.length = ary2;
    }
    if (this && this !== root_default && this instanceof wrapper) {
      fn = Ctor || createCtor_default(fn);
    }
    return fn.apply(thisBinding, args);
  }
  return wrapper;
}
var createHybrid_default = createHybrid;

// node_modules/lodash-es/_createCurry.js
function createCurry(func, bitmask, arity) {
  var Ctor = createCtor_default(func);
  function wrapper() {
    var length = arguments.length, args = Array(length), index = length, placeholder = getHolder_default(wrapper);
    while (index--) {
      args[index] = arguments[index];
    }
    var holders = length < 3 && args[0] !== placeholder && args[length - 1] !== placeholder ? [] : replaceHolders_default(args, placeholder);
    length -= holders.length;
    if (length < arity) {
      return createRecurry_default(func, bitmask, createHybrid_default, wrapper.placeholder, void 0, args, holders, void 0, void 0, arity - length);
    }
    var fn = this && this !== root_default && this instanceof wrapper ? Ctor : func;
    return apply_default(fn, this, args);
  }
  return wrapper;
}
var createCurry_default = createCurry;

// node_modules/lodash-es/_createPartial.js
var WRAP_BIND_FLAG5 = 1;
function createPartial(func, bitmask, thisArg, partials) {
  var isBind = bitmask & WRAP_BIND_FLAG5, Ctor = createCtor_default(func);
  function wrapper() {
    var argsIndex = -1, argsLength = arguments.length, leftIndex = -1, leftLength = partials.length, args = Array(leftLength + argsLength), fn = this && this !== root_default && this instanceof wrapper ? Ctor : func;
    while (++leftIndex < leftLength) {
      args[leftIndex] = partials[leftIndex];
    }
    while (argsLength--) {
      args[leftIndex++] = arguments[++argsIndex];
    }
    return apply_default(fn, isBind ? thisArg : this, args);
  }
  return wrapper;
}
var createPartial_default = createPartial;

// node_modules/lodash-es/_mergeData.js
var PLACEHOLDER2 = "__lodash_placeholder__";
var WRAP_BIND_FLAG6 = 1;
var WRAP_BIND_KEY_FLAG4 = 2;
var WRAP_CURRY_BOUND_FLAG2 = 4;
var WRAP_CURRY_FLAG4 = 8;
var WRAP_ARY_FLAG3 = 128;
var WRAP_REARG_FLAG2 = 256;
var nativeMin2 = Math.min;
function mergeData(data, source) {
  var bitmask = data[1], srcBitmask = source[1], newBitmask = bitmask | srcBitmask, isCommon = newBitmask < (WRAP_BIND_FLAG6 | WRAP_BIND_KEY_FLAG4 | WRAP_ARY_FLAG3);
  var isCombo = srcBitmask == WRAP_ARY_FLAG3 && bitmask == WRAP_CURRY_FLAG4 || srcBitmask == WRAP_ARY_FLAG3 && bitmask == WRAP_REARG_FLAG2 && data[7].length <= source[8] || srcBitmask == (WRAP_ARY_FLAG3 | WRAP_REARG_FLAG2) && source[7].length <= source[8] && bitmask == WRAP_CURRY_FLAG4;
  if (!(isCommon || isCombo)) {
    return data;
  }
  if (srcBitmask & WRAP_BIND_FLAG6) {
    data[2] = source[2];
    newBitmask |= bitmask & WRAP_BIND_FLAG6 ? 0 : WRAP_CURRY_BOUND_FLAG2;
  }
  var value = source[3];
  if (value) {
    var partials = data[3];
    data[3] = partials ? composeArgs_default(partials, value, source[4]) : value;
    data[4] = partials ? replaceHolders_default(data[3], PLACEHOLDER2) : source[4];
  }
  value = source[5];
  if (value) {
    partials = data[5];
    data[5] = partials ? composeArgsRight_default(partials, value, source[6]) : value;
    data[6] = partials ? replaceHolders_default(data[5], PLACEHOLDER2) : source[6];
  }
  value = source[7];
  if (value) {
    data[7] = value;
  }
  if (srcBitmask & WRAP_ARY_FLAG3) {
    data[8] = data[8] == null ? source[8] : nativeMin2(data[8], source[8]);
  }
  if (data[9] == null) {
    data[9] = source[9];
  }
  data[0] = source[0];
  data[1] = newBitmask;
  return data;
}
var mergeData_default = mergeData;

// node_modules/lodash-es/_createWrap.js
var FUNC_ERROR_TEXT2 = "Expected a function";
var WRAP_BIND_FLAG7 = 1;
var WRAP_BIND_KEY_FLAG5 = 2;
var WRAP_CURRY_FLAG5 = 8;
var WRAP_CURRY_RIGHT_FLAG3 = 16;
var WRAP_PARTIAL_FLAG3 = 32;
var WRAP_PARTIAL_RIGHT_FLAG3 = 64;
var nativeMax3 = Math.max;
function createWrap(func, bitmask, thisArg, partials, holders, argPos, ary2, arity) {
  var isBindKey = bitmask & WRAP_BIND_KEY_FLAG5;
  if (!isBindKey && typeof func != "function") {
    throw new TypeError(FUNC_ERROR_TEXT2);
  }
  var length = partials ? partials.length : 0;
  if (!length) {
    bitmask &= ~(WRAP_PARTIAL_FLAG3 | WRAP_PARTIAL_RIGHT_FLAG3);
    partials = holders = void 0;
  }
  ary2 = ary2 === void 0 ? ary2 : nativeMax3(toInteger_default(ary2), 0);
  arity = arity === void 0 ? arity : toInteger_default(arity);
  length -= holders ? holders.length : 0;
  if (bitmask & WRAP_PARTIAL_RIGHT_FLAG3) {
    var partialsRight = partials, holdersRight = holders;
    partials = holders = void 0;
  }
  var data = isBindKey ? void 0 : getData_default(func);
  var newData = [func, bitmask, thisArg, partials, holders, partialsRight, holdersRight, argPos, ary2, arity];
  if (data) {
    mergeData_default(newData, data);
  }
  func = newData[0];
  bitmask = newData[1];
  thisArg = newData[2];
  partials = newData[3];
  holders = newData[4];
  arity = newData[9] = newData[9] === void 0 ? isBindKey ? 0 : func.length : nativeMax3(newData[9] - length, 0);
  if (!arity && bitmask & (WRAP_CURRY_FLAG5 | WRAP_CURRY_RIGHT_FLAG3)) {
    bitmask &= ~(WRAP_CURRY_FLAG5 | WRAP_CURRY_RIGHT_FLAG3);
  }
  if (!bitmask || bitmask == WRAP_BIND_FLAG7) {
    var result2 = createBind_default(func, bitmask, thisArg);
  } else if (bitmask == WRAP_CURRY_FLAG5 || bitmask == WRAP_CURRY_RIGHT_FLAG3) {
    result2 = createCurry_default(func, bitmask, arity);
  } else if ((bitmask == WRAP_PARTIAL_FLAG3 || bitmask == (WRAP_BIND_FLAG7 | WRAP_PARTIAL_FLAG3)) && !holders.length) {
    result2 = createPartial_default(func, bitmask, thisArg, partials);
  } else {
    result2 = createHybrid_default.apply(void 0, newData);
  }
  var setter = data ? baseSetData_default : setData_default;
  return setWrapToString_default(setter(result2, newData), func, bitmask);
}
var createWrap_default = createWrap;

// node_modules/lodash-es/ary.js
var WRAP_ARY_FLAG4 = 128;
function ary(func, n, guard) {
  n = guard ? void 0 : n;
  n = func && n == null ? func.length : n;
  return createWrap_default(func, WRAP_ARY_FLAG4, void 0, void 0, void 0, void 0, n);
}
var ary_default = ary;

// node_modules/lodash-es/_baseAssignValue.js
function baseAssignValue(object, key, value) {
  if (key == "__proto__" && defineProperty_default) {
    defineProperty_default(object, key, {
      "configurable": true,
      "enumerable": true,
      "value": value,
      "writable": true
    });
  } else {
    object[key] = value;
  }
}
var baseAssignValue_default = baseAssignValue;

// node_modules/lodash-es/eq.js
function eq(value, other) {
  return value === other || value !== value && other !== other;
}
var eq_default = eq;

// node_modules/lodash-es/_assignValue.js
var objectProto6 = Object.prototype;
var hasOwnProperty5 = objectProto6.hasOwnProperty;
function assignValue(object, key, value) {
  var objValue = object[key];
  if (!(hasOwnProperty5.call(object, key) && eq_default(objValue, value)) || value === void 0 && !(key in object)) {
    baseAssignValue_default(object, key, value);
  }
}
var assignValue_default = assignValue;

// node_modules/lodash-es/_copyObject.js
function copyObject(source, props, object, customizer) {
  var isNew = !object;
  object || (object = {});
  var index = -1, length = props.length;
  while (++index < length) {
    var key = props[index];
    var newValue = customizer ? customizer(object[key], source[key], key, object, source) : void 0;
    if (newValue === void 0) {
      newValue = source[key];
    }
    if (isNew) {
      baseAssignValue_default(object, key, newValue);
    } else {
      assignValue_default(object, key, newValue);
    }
  }
  return object;
}
var copyObject_default = copyObject;

// node_modules/lodash-es/_overRest.js
var nativeMax4 = Math.max;
function overRest(func, start, transform2) {
  start = nativeMax4(start === void 0 ? func.length - 1 : start, 0);
  return function() {
    var args = arguments, index = -1, length = nativeMax4(args.length - start, 0), array = Array(length);
    while (++index < length) {
      array[index] = args[start + index];
    }
    index = -1;
    var otherArgs = Array(start + 1);
    while (++index < start) {
      otherArgs[index] = args[index];
    }
    otherArgs[start] = transform2(array);
    return apply_default(func, this, otherArgs);
  };
}
var overRest_default = overRest;

// node_modules/lodash-es/_baseRest.js
function baseRest(func, start) {
  return setToString_default(overRest_default(func, start, identity_default), func + "");
}
var baseRest_default = baseRest;

// node_modules/lodash-es/isLength.js
var MAX_SAFE_INTEGER2 = 9007199254740991;
function isLength(value) {
  return typeof value == "number" && value > -1 && value % 1 == 0 && value <= MAX_SAFE_INTEGER2;
}
var isLength_default = isLength;

// node_modules/lodash-es/isArrayLike.js
function isArrayLike(value) {
  return value != null && isLength_default(value.length) && !isFunction_default(value);
}
var isArrayLike_default = isArrayLike;

// node_modules/lodash-es/_isIterateeCall.js
function isIterateeCall(value, index, object) {
  if (!isObject_default(object)) {
    return false;
  }
  var type = typeof index;
  if (type == "number" ? isArrayLike_default(object) && isIndex_default(index, object.length) : type == "string" && index in object) {
    return eq_default(object[index], value);
  }
  return false;
}
var isIterateeCall_default = isIterateeCall;

// node_modules/lodash-es/_createAssigner.js
function createAssigner(assigner) {
  return baseRest_default(function(object, sources) {
    var index = -1, length = sources.length, customizer = length > 1 ? sources[length - 1] : void 0, guard = length > 2 ? sources[2] : void 0;
    customizer = assigner.length > 3 && typeof customizer == "function" ? (length--, customizer) : void 0;
    if (guard && isIterateeCall_default(sources[0], sources[1], guard)) {
      customizer = length < 3 ? void 0 : customizer;
      length = 1;
    }
    object = Object(object);
    while (++index < length) {
      var source = sources[index];
      if (source) {
        assigner(object, source, index, customizer);
      }
    }
    return object;
  });
}
var createAssigner_default = createAssigner;

// node_modules/lodash-es/_isPrototype.js
var objectProto7 = Object.prototype;
function isPrototype(value) {
  var Ctor = value && value.constructor, proto = typeof Ctor == "function" && Ctor.prototype || objectProto7;
  return value === proto;
}
var isPrototype_default = isPrototype;

// node_modules/lodash-es/_baseTimes.js
function baseTimes(n, iteratee2) {
  var index = -1, result2 = Array(n);
  while (++index < n) {
    result2[index] = iteratee2(index);
  }
  return result2;
}
var baseTimes_default = baseTimes;

// node_modules/lodash-es/_baseIsArguments.js
var argsTag = "[object Arguments]";
function baseIsArguments(value) {
  return isObjectLike_default(value) && baseGetTag_default(value) == argsTag;
}
var baseIsArguments_default = baseIsArguments;

// node_modules/lodash-es/isArguments.js
var objectProto8 = Object.prototype;
var hasOwnProperty6 = objectProto8.hasOwnProperty;
var propertyIsEnumerable = objectProto8.propertyIsEnumerable;
var isArguments = baseIsArguments_default(/* @__PURE__ */ function() {
  return arguments;
}()) ? baseIsArguments_default : function(value) {
  return isObjectLike_default(value) && hasOwnProperty6.call(value, "callee") && !propertyIsEnumerable.call(value, "callee");
};
var isArguments_default = isArguments;

// node_modules/lodash-es/stubFalse.js
function stubFalse() {
  return false;
}
var stubFalse_default = stubFalse;

// node_modules/lodash-es/isBuffer.js
var freeExports = typeof exports == "object" && exports && !exports.nodeType && exports;
var freeModule = freeExports && typeof module == "object" && module && !module.nodeType && module;
var moduleExports = freeModule && freeModule.exports === freeExports;
var Buffer = moduleExports ? root_default.Buffer : void 0;
var nativeIsBuffer = Buffer ? Buffer.isBuffer : void 0;
var isBuffer = nativeIsBuffer || stubFalse_default;
var isBuffer_default = isBuffer;

// node_modules/lodash-es/_baseIsTypedArray.js
var argsTag2 = "[object Arguments]";
var arrayTag = "[object Array]";
var boolTag = "[object Boolean]";
var dateTag = "[object Date]";
var errorTag = "[object Error]";
var funcTag2 = "[object Function]";
var mapTag = "[object Map]";
var numberTag = "[object Number]";
var objectTag = "[object Object]";
var regexpTag = "[object RegExp]";
var setTag = "[object Set]";
var stringTag = "[object String]";
var weakMapTag = "[object WeakMap]";
var arrayBufferTag = "[object ArrayBuffer]";
var dataViewTag = "[object DataView]";
var float32Tag = "[object Float32Array]";
var float64Tag = "[object Float64Array]";
var int8Tag = "[object Int8Array]";
var int16Tag = "[object Int16Array]";
var int32Tag = "[object Int32Array]";
var uint8Tag = "[object Uint8Array]";
var uint8ClampedTag = "[object Uint8ClampedArray]";
var uint16Tag = "[object Uint16Array]";
var uint32Tag = "[object Uint32Array]";
var typedArrayTags = {};
typedArrayTags[float32Tag] = typedArrayTags[float64Tag] = typedArrayTags[int8Tag] = typedArrayTags[int16Tag] = typedArrayTags[int32Tag] = typedArrayTags[uint8Tag] = typedArrayTags[uint8ClampedTag] = typedArrayTags[uint16Tag] = typedArrayTags[uint32Tag] = true;
typedArrayTags[argsTag2] = typedArrayTags[arrayTag] = typedArrayTags[arrayBufferTag] = typedArrayTags[boolTag] = typedArrayTags[dataViewTag] = typedArrayTags[dateTag] = typedArrayTags[errorTag] = typedArrayTags[funcTag2] = typedArrayTags[mapTag] = typedArrayTags[numberTag] = typedArrayTags[objectTag] = typedArrayTags[regexpTag] = typedArrayTags[setTag] = typedArrayTags[stringTag] = typedArrayTags[weakMapTag] = false;
function baseIsTypedArray(value) {
  return isObjectLike_default(value) && isLength_default(value.length) && !!typedArrayTags[baseGetTag_default(value)];
}
var baseIsTypedArray_default = baseIsTypedArray;

// node_modules/lodash-es/_baseUnary.js
function baseUnary(func) {
  return function(value) {
    return func(value);
  };
}
var baseUnary_default = baseUnary;

// node_modules/lodash-es/_nodeUtil.js
var freeExports2 = typeof exports == "object" && exports && !exports.nodeType && exports;
var freeModule2 = freeExports2 && typeof module == "object" && module && !module.nodeType && module;
var moduleExports2 = freeModule2 && freeModule2.exports === freeExports2;
var freeProcess = moduleExports2 && freeGlobal_default.process;
var nodeUtil = function() {
  try {
    var types = freeModule2 && freeModule2.require && freeModule2.require("util").types;
    if (types) {
      return types;
    }
    return freeProcess && freeProcess.binding && freeProcess.binding("util");
  } catch (e) {
  }
}();
var nodeUtil_default = nodeUtil;

// node_modules/lodash-es/isTypedArray.js
var nodeIsTypedArray = nodeUtil_default && nodeUtil_default.isTypedArray;
var isTypedArray = nodeIsTypedArray ? baseUnary_default(nodeIsTypedArray) : baseIsTypedArray_default;
var isTypedArray_default = isTypedArray;

// node_modules/lodash-es/_arrayLikeKeys.js
var objectProto9 = Object.prototype;
var hasOwnProperty7 = objectProto9.hasOwnProperty;
function arrayLikeKeys(value, inherited) {
  var isArr = isArray_default(value), isArg = !isArr && isArguments_default(value), isBuff = !isArr && !isArg && isBuffer_default(value), isType = !isArr && !isArg && !isBuff && isTypedArray_default(value), skipIndexes = isArr || isArg || isBuff || isType, result2 = skipIndexes ? baseTimes_default(value.length, String) : [], length = result2.length;
  for (var key in value) {
    if ((inherited || hasOwnProperty7.call(value, key)) && !(skipIndexes && // Safari 9 has enumerable `arguments.length` in strict mode.
    (key == "length" || // Node.js 0.10 has enumerable non-index properties on buffers.
    isBuff && (key == "offset" || key == "parent") || // PhantomJS 2 has enumerable non-index properties on typed arrays.
    isType && (key == "buffer" || key == "byteLength" || key == "byteOffset") || // Skip index properties.
    isIndex_default(key, length)))) {
      result2.push(key);
    }
  }
  return result2;
}
var arrayLikeKeys_default = arrayLikeKeys;

// node_modules/lodash-es/_overArg.js
function overArg(func, transform2) {
  return function(arg) {
    return func(transform2(arg));
  };
}
var overArg_default = overArg;

// node_modules/lodash-es/_nativeKeys.js
var nativeKeys = overArg_default(Object.keys, Object);
var nativeKeys_default = nativeKeys;

// node_modules/lodash-es/_baseKeys.js
var objectProto10 = Object.prototype;
var hasOwnProperty8 = objectProto10.hasOwnProperty;
function baseKeys(object) {
  if (!isPrototype_default(object)) {
    return nativeKeys_default(object);
  }
  var result2 = [];
  for (var key in Object(object)) {
    if (hasOwnProperty8.call(object, key) && key != "constructor") {
      result2.push(key);
    }
  }
  return result2;
}
var baseKeys_default = baseKeys;

// node_modules/lodash-es/keys.js
function keys(object) {
  return isArrayLike_default(object) ? arrayLikeKeys_default(object) : baseKeys_default(object);
}
var keys_default = keys;

// node_modules/lodash-es/assign.js
var objectProto11 = Object.prototype;
var hasOwnProperty9 = objectProto11.hasOwnProperty;
var assign = createAssigner_default(function(object, source) {
  if (isPrototype_default(source) || isArrayLike_default(source)) {
    copyObject_default(source, keys_default(source), object);
    return;
  }
  for (var key in source) {
    if (hasOwnProperty9.call(source, key)) {
      assignValue_default(object, key, source[key]);
    }
  }
});
var assign_default = assign;

// node_modules/lodash-es/_nativeKeysIn.js
function nativeKeysIn(object) {
  var result2 = [];
  if (object != null) {
    for (var key in Object(object)) {
      result2.push(key);
    }
  }
  return result2;
}
var nativeKeysIn_default = nativeKeysIn;

// node_modules/lodash-es/_baseKeysIn.js
var objectProto12 = Object.prototype;
var hasOwnProperty10 = objectProto12.hasOwnProperty;
function baseKeysIn(object) {
  if (!isObject_default(object)) {
    return nativeKeysIn_default(object);
  }
  var isProto = isPrototype_default(object), result2 = [];
  for (var key in object) {
    if (!(key == "constructor" && (isProto || !hasOwnProperty10.call(object, key)))) {
      result2.push(key);
    }
  }
  return result2;
}
var baseKeysIn_default = baseKeysIn;

// node_modules/lodash-es/keysIn.js
function keysIn(object) {
  return isArrayLike_default(object) ? arrayLikeKeys_default(object, true) : baseKeysIn_default(object);
}
var keysIn_default = keysIn;

// node_modules/lodash-es/assignIn.js
var assignIn = createAssigner_default(function(object, source) {
  copyObject_default(source, keysIn_default(source), object);
});
var assignIn_default = assignIn;

// node_modules/lodash-es/assignInWith.js
var assignInWith = createAssigner_default(function(object, source, srcIndex, customizer) {
  copyObject_default(source, keysIn_default(source), object, customizer);
});
var assignInWith_default = assignInWith;

// node_modules/lodash-es/assignWith.js
var assignWith = createAssigner_default(function(object, source, srcIndex, customizer) {
  copyObject_default(source, keys_default(source), object, customizer);
});
var assignWith_default = assignWith;

// node_modules/lodash-es/_isKey.js
var reIsDeepProp = /\.|\[(?:[^[\]]*|(["'])(?:(?!\1)[^\\]|\\.)*?\1)\]/;
var reIsPlainProp = /^\w*$/;
function isKey(value, object) {
  if (isArray_default(value)) {
    return false;
  }
  var type = typeof value;
  if (type == "number" || type == "symbol" || type == "boolean" || value == null || isSymbol_default(value)) {
    return true;
  }
  return reIsPlainProp.test(value) || !reIsDeepProp.test(value) || object != null && value in Object(object);
}
var isKey_default = isKey;

// node_modules/lodash-es/_nativeCreate.js
var nativeCreate = getNative_default(Object, "create");
var nativeCreate_default = nativeCreate;

// node_modules/lodash-es/_hashClear.js
function hashClear() {
  this.__data__ = nativeCreate_default ? nativeCreate_default(null) : {};
  this.size = 0;
}
var hashClear_default = hashClear;

// node_modules/lodash-es/_hashDelete.js
function hashDelete(key) {
  var result2 = this.has(key) && delete this.__data__[key];
  this.size -= result2 ? 1 : 0;
  return result2;
}
var hashDelete_default = hashDelete;

// node_modules/lodash-es/_hashGet.js
var HASH_UNDEFINED = "__lodash_hash_undefined__";
var objectProto13 = Object.prototype;
var hasOwnProperty11 = objectProto13.hasOwnProperty;
function hashGet(key) {
  var data = this.__data__;
  if (nativeCreate_default) {
    var result2 = data[key];
    return result2 === HASH_UNDEFINED ? void 0 : result2;
  }
  return hasOwnProperty11.call(data, key) ? data[key] : void 0;
}
var hashGet_default = hashGet;

// node_modules/lodash-es/_hashHas.js
var objectProto14 = Object.prototype;
var hasOwnProperty12 = objectProto14.hasOwnProperty;
function hashHas(key) {
  var data = this.__data__;
  return nativeCreate_default ? data[key] !== void 0 : hasOwnProperty12.call(data, key);
}
var hashHas_default = hashHas;

// node_modules/lodash-es/_hashSet.js
var HASH_UNDEFINED2 = "__lodash_hash_undefined__";
function hashSet(key, value) {
  var data = this.__data__;
  this.size += this.has(key) ? 0 : 1;
  data[key] = nativeCreate_default && value === void 0 ? HASH_UNDEFINED2 : value;
  return this;
}
var hashSet_default = hashSet;

// node_modules/lodash-es/_Hash.js
function Hash(entries) {
  var index = -1, length = entries == null ? 0 : entries.length;
  this.clear();
  while (++index < length) {
    var entry = entries[index];
    this.set(entry[0], entry[1]);
  }
}
Hash.prototype.clear = hashClear_default;
Hash.prototype["delete"] = hashDelete_default;
Hash.prototype.get = hashGet_default;
Hash.prototype.has = hashHas_default;
Hash.prototype.set = hashSet_default;
var Hash_default = Hash;

// node_modules/lodash-es/_listCacheClear.js
function listCacheClear() {
  this.__data__ = [];
  this.size = 0;
}
var listCacheClear_default = listCacheClear;

// node_modules/lodash-es/_assocIndexOf.js
function assocIndexOf(array, key) {
  var length = array.length;
  while (length--) {
    if (eq_default(array[length][0], key)) {
      return length;
    }
  }
  return -1;
}
var assocIndexOf_default = assocIndexOf;

// node_modules/lodash-es/_listCacheDelete.js
var arrayProto = Array.prototype;
var splice = arrayProto.splice;
function listCacheDelete(key) {
  var data = this.__data__, index = assocIndexOf_default(data, key);
  if (index < 0) {
    return false;
  }
  var lastIndex = data.length - 1;
  if (index == lastIndex) {
    data.pop();
  } else {
    splice.call(data, index, 1);
  }
  --this.size;
  return true;
}
var listCacheDelete_default = listCacheDelete;

// node_modules/lodash-es/_listCacheGet.js
function listCacheGet(key) {
  var data = this.__data__, index = assocIndexOf_default(data, key);
  return index < 0 ? void 0 : data[index][1];
}
var listCacheGet_default = listCacheGet;

// node_modules/lodash-es/_listCacheHas.js
function listCacheHas(key) {
  return assocIndexOf_default(this.__data__, key) > -1;
}
var listCacheHas_default = listCacheHas;

// node_modules/lodash-es/_listCacheSet.js
function listCacheSet(key, value) {
  var data = this.__data__, index = assocIndexOf_default(data, key);
  if (index < 0) {
    ++this.size;
    data.push([key, value]);
  } else {
    data[index][1] = value;
  }
  return this;
}
var listCacheSet_default = listCacheSet;

// node_modules/lodash-es/_ListCache.js
function ListCache(entries) {
  var index = -1, length = entries == null ? 0 : entries.length;
  this.clear();
  while (++index < length) {
    var entry = entries[index];
    this.set(entry[0], entry[1]);
  }
}
ListCache.prototype.clear = listCacheClear_default;
ListCache.prototype["delete"] = listCacheDelete_default;
ListCache.prototype.get = listCacheGet_default;
ListCache.prototype.has = listCacheHas_default;
ListCache.prototype.set = listCacheSet_default;
var ListCache_default = ListCache;

// node_modules/lodash-es/_Map.js
var Map = getNative_default(root_default, "Map");
var Map_default = Map;

// node_modules/lodash-es/_mapCacheClear.js
function mapCacheClear() {
  this.size = 0;
  this.__data__ = {
    "hash": new Hash_default(),
    "map": new (Map_default || ListCache_default)(),
    "string": new Hash_default()
  };
}
var mapCacheClear_default = mapCacheClear;

// node_modules/lodash-es/_isKeyable.js
function isKeyable(value) {
  var type = typeof value;
  return type == "string" || type == "number" || type == "symbol" || type == "boolean" ? value !== "__proto__" : value === null;
}
var isKeyable_default = isKeyable;

// node_modules/lodash-es/_getMapData.js
function getMapData(map2, key) {
  var data = map2.__data__;
  return isKeyable_default(key) ? data[typeof key == "string" ? "string" : "hash"] : data.map;
}
var getMapData_default = getMapData;

// node_modules/lodash-es/_mapCacheDelete.js
function mapCacheDelete(key) {
  var result2 = getMapData_default(this, key)["delete"](key);
  this.size -= result2 ? 1 : 0;
  return result2;
}
var mapCacheDelete_default = mapCacheDelete;

// node_modules/lodash-es/_mapCacheGet.js
function mapCacheGet(key) {
  return getMapData_default(this, key).get(key);
}
var mapCacheGet_default = mapCacheGet;

// node_modules/lodash-es/_mapCacheHas.js
function mapCacheHas(key) {
  return getMapData_default(this, key).has(key);
}
var mapCacheHas_default = mapCacheHas;

// node_modules/lodash-es/_mapCacheSet.js
function mapCacheSet(key, value) {
  var data = getMapData_default(this, key), size2 = data.size;
  data.set(key, value);
  this.size += data.size == size2 ? 0 : 1;
  return this;
}
var mapCacheSet_default = mapCacheSet;

// node_modules/lodash-es/_MapCache.js
function MapCache(entries) {
  var index = -1, length = entries == null ? 0 : entries.length;
  this.clear();
  while (++index < length) {
    var entry = entries[index];
    this.set(entry[0], entry[1]);
  }
}
MapCache.prototype.clear = mapCacheClear_default;
MapCache.prototype["delete"] = mapCacheDelete_default;
MapCache.prototype.get = mapCacheGet_default;
MapCache.prototype.has = mapCacheHas_default;
MapCache.prototype.set = mapCacheSet_default;
var MapCache_default = MapCache;

// node_modules/lodash-es/memoize.js
var FUNC_ERROR_TEXT3 = "Expected a function";
function memoize(func, resolver) {
  if (typeof func != "function" || resolver != null && typeof resolver != "function") {
    throw new TypeError(FUNC_ERROR_TEXT3);
  }
  var memoized = function() {
    var args = arguments, key = resolver ? resolver.apply(this, args) : args[0], cache = memoized.cache;
    if (cache.has(key)) {
      return cache.get(key);
    }
    var result2 = func.apply(this, args);
    memoized.cache = cache.set(key, result2) || cache;
    return result2;
  };
  memoized.cache = new (memoize.Cache || MapCache_default)();
  return memoized;
}
memoize.Cache = MapCache_default;
var memoize_default = memoize;

// node_modules/lodash-es/_memoizeCapped.js
var MAX_MEMOIZE_SIZE = 500;
function memoizeCapped(func) {
  var result2 = memoize_default(func, function(key) {
    if (cache.size === MAX_MEMOIZE_SIZE) {
      cache.clear();
    }
    return key;
  });
  var cache = result2.cache;
  return result2;
}
var memoizeCapped_default = memoizeCapped;

// node_modules/lodash-es/_stringToPath.js
var rePropName = /[^.[\]]+|\[(?:(-?\d+(?:\.\d+)?)|(["'])((?:(?!\2)[^\\]|\\.)*?)\2)\]|(?=(?:\.|\[\])(?:\.|\[\]|$))/g;
var reEscapeChar = /\\(\\)?/g;
var stringToPath = memoizeCapped_default(function(string) {
  var result2 = [];
  if (string.charCodeAt(0) === 46) {
    result2.push("");
  }
  string.replace(rePropName, function(match2, number, quote, subString) {
    result2.push(quote ? subString.replace(reEscapeChar, "$1") : number || match2);
  });
  return result2;
});
var stringToPath_default = stringToPath;

// node_modules/lodash-es/toString.js
function toString(value) {
  return value == null ? "" : baseToString_default(value);
}
var toString_default = toString;

// node_modules/lodash-es/_castPath.js
function castPath(value, object) {
  if (isArray_default(value)) {
    return value;
  }
  return isKey_default(value, object) ? [value] : stringToPath_default(toString_default(value));
}
var castPath_default = castPath;

// node_modules/lodash-es/_toKey.js
var INFINITY3 = 1 / 0;
function toKey(value) {
  if (typeof value == "string" || isSymbol_default(value)) {
    return value;
  }
  var result2 = value + "";
  return result2 == "0" && 1 / value == -INFINITY3 ? "-0" : result2;
}
var toKey_default = toKey;

// node_modules/lodash-es/_baseGet.js
function baseGet(object, path) {
  path = castPath_default(path, object);
  var index = 0, length = path.length;
  while (object != null && index < length) {
    object = object[toKey_default(path[index++])];
  }
  return index && index == length ? object : void 0;
}
var baseGet_default = baseGet;

// node_modules/lodash-es/get.js
function get(object, path, defaultValue) {
  var result2 = object == null ? void 0 : baseGet_default(object, path);
  return result2 === void 0 ? defaultValue : result2;
}
var get_default = get;

// node_modules/lodash-es/_baseAt.js
function baseAt(object, paths) {
  var index = -1, length = paths.length, result2 = Array(length), skip = object == null;
  while (++index < length) {
    result2[index] = skip ? void 0 : get_default(object, paths[index]);
  }
  return result2;
}
var baseAt_default = baseAt;

// node_modules/lodash-es/_arrayPush.js
function arrayPush(array, values2) {
  var index = -1, length = values2.length, offset = array.length;
  while (++index < length) {
    array[offset + index] = values2[index];
  }
  return array;
}
var arrayPush_default = arrayPush;

// node_modules/lodash-es/_isFlattenable.js
var spreadableSymbol = Symbol_default ? Symbol_default.isConcatSpreadable : void 0;
function isFlattenable(value) {
  return isArray_default(value) || isArguments_default(value) || !!(spreadableSymbol && value && value[spreadableSymbol]);
}
var isFlattenable_default = isFlattenable;

// node_modules/lodash-es/_baseFlatten.js
function baseFlatten(array, depth, predicate, isStrict, result2) {
  var index = -1, length = array.length;
  predicate || (predicate = isFlattenable_default);
  result2 || (result2 = []);
  while (++index < length) {
    var value = array[index];
    if (depth > 0 && predicate(value)) {
      if (depth > 1) {
        baseFlatten(value, depth - 1, predicate, isStrict, result2);
      } else {
        arrayPush_default(result2, value);
      }
    } else if (!isStrict) {
      result2[result2.length] = value;
    }
  }
  return result2;
}
var baseFlatten_default = baseFlatten;

// node_modules/lodash-es/flatten.js
function flatten(array) {
  var length = array == null ? 0 : array.length;
  return length ? baseFlatten_default(array, 1) : [];
}
var flatten_default = flatten;

// node_modules/lodash-es/_flatRest.js
function flatRest(func) {
  return setToString_default(overRest_default(func, void 0, flatten_default), func + "");
}
var flatRest_default = flatRest;

// node_modules/lodash-es/at.js
var at = flatRest_default(baseAt_default);
var at_default = at;

// node_modules/lodash-es/_getPrototype.js
var getPrototype = overArg_default(Object.getPrototypeOf, Object);
var getPrototype_default = getPrototype;

// node_modules/lodash-es/isPlainObject.js
var objectTag2 = "[object Object]";
var funcProto3 = Function.prototype;
var objectProto15 = Object.prototype;
var funcToString3 = funcProto3.toString;
var hasOwnProperty13 = objectProto15.hasOwnProperty;
var objectCtorString = funcToString3.call(Object);
function isPlainObject(value) {
  if (!isObjectLike_default(value) || baseGetTag_default(value) != objectTag2) {
    return false;
  }
  var proto = getPrototype_default(value);
  if (proto === null) {
    return true;
  }
  var Ctor = hasOwnProperty13.call(proto, "constructor") && proto.constructor;
  return typeof Ctor == "function" && Ctor instanceof Ctor && funcToString3.call(Ctor) == objectCtorString;
}
var isPlainObject_default = isPlainObject;

// node_modules/lodash-es/isError.js
var domExcTag = "[object DOMException]";
var errorTag2 = "[object Error]";
function isError(value) {
  if (!isObjectLike_default(value)) {
    return false;
  }
  var tag = baseGetTag_default(value);
  return tag == errorTag2 || tag == domExcTag || typeof value.message == "string" && typeof value.name == "string" && !isPlainObject_default(value);
}
var isError_default = isError;

// node_modules/lodash-es/attempt.js
var attempt = baseRest_default(function(func, args) {
  try {
    return apply_default(func, void 0, args);
  } catch (e) {
    return isError_default(e) ? e : new Error(e);
  }
});
var attempt_default = attempt;

// node_modules/lodash-es/before.js
var FUNC_ERROR_TEXT4 = "Expected a function";
function before(n, func) {
  var result2;
  if (typeof func != "function") {
    throw new TypeError(FUNC_ERROR_TEXT4);
  }
  n = toInteger_default(n);
  return function() {
    if (--n > 0) {
      result2 = func.apply(this, arguments);
    }
    if (n <= 1) {
      func = void 0;
    }
    return result2;
  };
}
var before_default = before;

// node_modules/lodash-es/bind.js
var WRAP_BIND_FLAG8 = 1;
var WRAP_PARTIAL_FLAG4 = 32;
var bind = baseRest_default(function(func, thisArg, partials) {
  var bitmask = WRAP_BIND_FLAG8;
  if (partials.length) {
    var holders = replaceHolders_default(partials, getHolder_default(bind));
    bitmask |= WRAP_PARTIAL_FLAG4;
  }
  return createWrap_default(func, bitmask, thisArg, partials, holders);
});
bind.placeholder = {};
var bind_default = bind;

// node_modules/lodash-es/bindAll.js
var bindAll = flatRest_default(function(object, methodNames) {
  arrayEach_default(methodNames, function(key) {
    key = toKey_default(key);
    baseAssignValue_default(object, key, bind_default(object[key], object));
  });
  return object;
});
var bindAll_default = bindAll;

// node_modules/lodash-es/bindKey.js
var WRAP_BIND_FLAG9 = 1;
var WRAP_BIND_KEY_FLAG6 = 2;
var WRAP_PARTIAL_FLAG5 = 32;
var bindKey = baseRest_default(function(object, key, partials) {
  var bitmask = WRAP_BIND_FLAG9 | WRAP_BIND_KEY_FLAG6;
  if (partials.length) {
    var holders = replaceHolders_default(partials, getHolder_default(bindKey));
    bitmask |= WRAP_PARTIAL_FLAG5;
  }
  return createWrap_default(key, bitmask, object, partials, holders);
});
bindKey.placeholder = {};
var bindKey_default = bindKey;

// node_modules/lodash-es/_baseSlice.js
function baseSlice(array, start, end) {
  var index = -1, length = array.length;
  if (start < 0) {
    start = -start > length ? 0 : length + start;
  }
  end = end > length ? length : end;
  if (end < 0) {
    end += length;
  }
  length = start > end ? 0 : end - start >>> 0;
  start >>>= 0;
  var result2 = Array(length);
  while (++index < length) {
    result2[index] = array[index + start];
  }
  return result2;
}
var baseSlice_default = baseSlice;

// node_modules/lodash-es/_castSlice.js
function castSlice(array, start, end) {
  var length = array.length;
  end = end === void 0 ? length : end;
  return !start && end >= length ? array : baseSlice_default(array, start, end);
}
var castSlice_default = castSlice;

// node_modules/lodash-es/_hasUnicode.js
var rsAstralRange = "\\ud800-\\udfff";
var rsComboMarksRange = "\\u0300-\\u036f";
var reComboHalfMarksRange = "\\ufe20-\\ufe2f";
var rsComboSymbolsRange = "\\u20d0-\\u20ff";
var rsComboRange = rsComboMarksRange + reComboHalfMarksRange + rsComboSymbolsRange;
var rsVarRange = "\\ufe0e\\ufe0f";
var rsZWJ = "\\u200d";
var reHasUnicode = RegExp("[" + rsZWJ + rsAstralRange + rsComboRange + rsVarRange + "]");
function hasUnicode(string) {
  return reHasUnicode.test(string);
}
var hasUnicode_default = hasUnicode;

// node_modules/lodash-es/_asciiToArray.js
function asciiToArray(string) {
  return string.split("");
}
var asciiToArray_default = asciiToArray;

// node_modules/lodash-es/_unicodeToArray.js
var rsAstralRange2 = "\\ud800-\\udfff";
var rsComboMarksRange2 = "\\u0300-\\u036f";
var reComboHalfMarksRange2 = "\\ufe20-\\ufe2f";
var rsComboSymbolsRange2 = "\\u20d0-\\u20ff";
var rsComboRange2 = rsComboMarksRange2 + reComboHalfMarksRange2 + rsComboSymbolsRange2;
var rsVarRange2 = "\\ufe0e\\ufe0f";
var rsAstral = "[" + rsAstralRange2 + "]";
var rsCombo = "[" + rsComboRange2 + "]";
var rsFitz = "\\ud83c[\\udffb-\\udfff]";
var rsModifier = "(?:" + rsCombo + "|" + rsFitz + ")";
var rsNonAstral = "[^" + rsAstralRange2 + "]";
var rsRegional = "(?:\\ud83c[\\udde6-\\uddff]){2}";
var rsSurrPair = "[\\ud800-\\udbff][\\udc00-\\udfff]";
var rsZWJ2 = "\\u200d";
var reOptMod = rsModifier + "?";
var rsOptVar = "[" + rsVarRange2 + "]?";
var rsOptJoin = "(?:" + rsZWJ2 + "(?:" + [rsNonAstral, rsRegional, rsSurrPair].join("|") + ")" + rsOptVar + reOptMod + ")*";
var rsSeq = rsOptVar + reOptMod + rsOptJoin;
var rsSymbol = "(?:" + [rsNonAstral + rsCombo + "?", rsCombo, rsRegional, rsSurrPair, rsAstral].join("|") + ")";
var reUnicode = RegExp(rsFitz + "(?=" + rsFitz + ")|" + rsSymbol + rsSeq, "g");
function unicodeToArray(string) {
  return string.match(reUnicode) || [];
}
var unicodeToArray_default = unicodeToArray;

// node_modules/lodash-es/_stringToArray.js
function stringToArray(string) {
  return hasUnicode_default(string) ? unicodeToArray_default(string) : asciiToArray_default(string);
}
var stringToArray_default = stringToArray;

// node_modules/lodash-es/_createCaseFirst.js
function createCaseFirst(methodName) {
  return function(string) {
    string = toString_default(string);
    var strSymbols = hasUnicode_default(string) ? stringToArray_default(string) : void 0;
    var chr = strSymbols ? strSymbols[0] : string.charAt(0);
    var trailing = strSymbols ? castSlice_default(strSymbols, 1).join("") : string.slice(1);
    return chr[methodName]() + trailing;
  };
}
var createCaseFirst_default = createCaseFirst;

// node_modules/lodash-es/upperFirst.js
var upperFirst = createCaseFirst_default("toUpperCase");
var upperFirst_default = upperFirst;

// node_modules/lodash-es/capitalize.js
function capitalize(string) {
  return upperFirst_default(toString_default(string).toLowerCase());
}
var capitalize_default = capitalize;

// node_modules/lodash-es/_arrayReduce.js
function arrayReduce(array, iteratee2, accumulator, initAccum) {
  var index = -1, length = array == null ? 0 : array.length;
  if (initAccum && length) {
    accumulator = array[++index];
  }
  while (++index < length) {
    accumulator = iteratee2(accumulator, array[index], index, array);
  }
  return accumulator;
}
var arrayReduce_default = arrayReduce;

// node_modules/lodash-es/_basePropertyOf.js
function basePropertyOf(object) {
  return function(key) {
    return object == null ? void 0 : object[key];
  };
}
var basePropertyOf_default = basePropertyOf;

// node_modules/lodash-es/_deburrLetter.js
var deburredLetters = {
  // Latin-1 Supplement block.
  "À": "A",
  "Á": "A",
  "Â": "A",
  "Ã": "A",
  "Ä": "A",
  "Å": "A",
  "à": "a",
  "á": "a",
  "â": "a",
  "ã": "a",
  "ä": "a",
  "å": "a",
  "Ç": "C",
  "ç": "c",
  "Ð": "D",
  "ð": "d",
  "È": "E",
  "É": "E",
  "Ê": "E",
  "Ë": "E",
  "è": "e",
  "é": "e",
  "ê": "e",
  "ë": "e",
  "Ì": "I",
  "Í": "I",
  "Î": "I",
  "Ï": "I",
  "ì": "i",
  "í": "i",
  "î": "i",
  "ï": "i",
  "Ñ": "N",
  "ñ": "n",
  "Ò": "O",
  "Ó": "O",
  "Ô": "O",
  "Õ": "O",
  "Ö": "O",
  "Ø": "O",
  "ò": "o",
  "ó": "o",
  "ô": "o",
  "õ": "o",
  "ö": "o",
  "ø": "o",
  "Ù": "U",
  "Ú": "U",
  "Û": "U",
  "Ü": "U",
  "ù": "u",
  "ú": "u",
  "û": "u",
  "ü": "u",
  "Ý": "Y",
  "ý": "y",
  "ÿ": "y",
  "Æ": "Ae",
  "æ": "ae",
  "Þ": "Th",
  "þ": "th",
  "ß": "ss",
  // Latin Extended-A block.
  "Ā": "A",
  "Ă": "A",
  "Ą": "A",
  "ā": "a",
  "ă": "a",
  "ą": "a",
  "Ć": "C",
  "Ĉ": "C",
  "Ċ": "C",
  "Č": "C",
  "ć": "c",
  "ĉ": "c",
  "ċ": "c",
  "č": "c",
  "Ď": "D",
  "Đ": "D",
  "ď": "d",
  "đ": "d",
  "Ē": "E",
  "Ĕ": "E",
  "Ė": "E",
  "Ę": "E",
  "Ě": "E",
  "ē": "e",
  "ĕ": "e",
  "ė": "e",
  "ę": "e",
  "ě": "e",
  "Ĝ": "G",
  "Ğ": "G",
  "Ġ": "G",
  "Ģ": "G",
  "ĝ": "g",
  "ğ": "g",
  "ġ": "g",
  "ģ": "g",
  "Ĥ": "H",
  "Ħ": "H",
  "ĥ": "h",
  "ħ": "h",
  "Ĩ": "I",
  "Ī": "I",
  "Ĭ": "I",
  "Į": "I",
  "İ": "I",
  "ĩ": "i",
  "ī": "i",
  "ĭ": "i",
  "į": "i",
  "ı": "i",
  "Ĵ": "J",
  "ĵ": "j",
  "Ķ": "K",
  "ķ": "k",
  "ĸ": "k",
  "Ĺ": "L",
  "Ļ": "L",
  "Ľ": "L",
  "Ŀ": "L",
  "Ł": "L",
  "ĺ": "l",
  "ļ": "l",
  "ľ": "l",
  "ŀ": "l",
  "ł": "l",
  "Ń": "N",
  "Ņ": "N",
  "Ň": "N",
  "Ŋ": "N",
  "ń": "n",
  "ņ": "n",
  "ň": "n",
  "ŋ": "n",
  "Ō": "O",
  "Ŏ": "O",
  "Ő": "O",
  "ō": "o",
  "ŏ": "o",
  "ő": "o",
  "Ŕ": "R",
  "Ŗ": "R",
  "Ř": "R",
  "ŕ": "r",
  "ŗ": "r",
  "ř": "r",
  "Ś": "S",
  "Ŝ": "S",
  "Ş": "S",
  "Š": "S",
  "ś": "s",
  "ŝ": "s",
  "ş": "s",
  "š": "s",
  "Ţ": "T",
  "Ť": "T",
  "Ŧ": "T",
  "ţ": "t",
  "ť": "t",
  "ŧ": "t",
  "Ũ": "U",
  "Ū": "U",
  "Ŭ": "U",
  "Ů": "U",
  "Ű": "U",
  "Ų": "U",
  "ũ": "u",
  "ū": "u",
  "ŭ": "u",
  "ů": "u",
  "ű": "u",
  "ų": "u",
  "Ŵ": "W",
  "ŵ": "w",
  "Ŷ": "Y",
  "ŷ": "y",
  "Ÿ": "Y",
  "Ź": "Z",
  "Ż": "Z",
  "Ž": "Z",
  "ź": "z",
  "ż": "z",
  "ž": "z",
  "Ĳ": "IJ",
  "ĳ": "ij",
  "Œ": "Oe",
  "œ": "oe",
  "ŉ": "'n",
  "ſ": "s"
};
var deburrLetter = basePropertyOf_default(deburredLetters);
var deburrLetter_default = deburrLetter;

// node_modules/lodash-es/deburr.js
var reLatin = /[\xc0-\xd6\xd8-\xf6\xf8-\xff\u0100-\u017f]/g;
var rsComboMarksRange3 = "\\u0300-\\u036f";
var reComboHalfMarksRange3 = "\\ufe20-\\ufe2f";
var rsComboSymbolsRange3 = "\\u20d0-\\u20ff";
var rsComboRange3 = rsComboMarksRange3 + reComboHalfMarksRange3 + rsComboSymbolsRange3;
var rsCombo2 = "[" + rsComboRange3 + "]";
var reComboMark = RegExp(rsCombo2, "g");
function deburr(string) {
  string = toString_default(string);
  return string && string.replace(reLatin, deburrLetter_default).replace(reComboMark, "");
}
var deburr_default = deburr;

// node_modules/lodash-es/_asciiWords.js
var reAsciiWord = /[^\x00-\x2f\x3a-\x40\x5b-\x60\x7b-\x7f]+/g;
function asciiWords(string) {
  return string.match(reAsciiWord) || [];
}
var asciiWords_default = asciiWords;

// node_modules/lodash-es/_hasUnicodeWord.js
var reHasUnicodeWord = /[a-z][A-Z]|[A-Z]{2}[a-z]|[0-9][a-zA-Z]|[a-zA-Z][0-9]|[^a-zA-Z0-9 ]/;
function hasUnicodeWord(string) {
  return reHasUnicodeWord.test(string);
}
var hasUnicodeWord_default = hasUnicodeWord;

// node_modules/lodash-es/_unicodeWords.js
var rsAstralRange3 = "\\ud800-\\udfff";
var rsComboMarksRange4 = "\\u0300-\\u036f";
var reComboHalfMarksRange4 = "\\ufe20-\\ufe2f";
var rsComboSymbolsRange4 = "\\u20d0-\\u20ff";
var rsComboRange4 = rsComboMarksRange4 + reComboHalfMarksRange4 + rsComboSymbolsRange4;
var rsDingbatRange = "\\u2700-\\u27bf";
var rsLowerRange = "a-z\\xdf-\\xf6\\xf8-\\xff";
var rsMathOpRange = "\\xac\\xb1\\xd7\\xf7";
var rsNonCharRange = "\\x00-\\x2f\\x3a-\\x40\\x5b-\\x60\\x7b-\\xbf";
var rsPunctuationRange = "\\u2000-\\u206f";
var rsSpaceRange = " \\t\\x0b\\f\\xa0\\ufeff\\n\\r\\u2028\\u2029\\u1680\\u180e\\u2000\\u2001\\u2002\\u2003\\u2004\\u2005\\u2006\\u2007\\u2008\\u2009\\u200a\\u202f\\u205f\\u3000";
var rsUpperRange = "A-Z\\xc0-\\xd6\\xd8-\\xde";
var rsVarRange3 = "\\ufe0e\\ufe0f";
var rsBreakRange = rsMathOpRange + rsNonCharRange + rsPunctuationRange + rsSpaceRange;
var rsApos = "['’]";
var rsBreak = "[" + rsBreakRange + "]";
var rsCombo3 = "[" + rsComboRange4 + "]";
var rsDigits = "\\d+";
var rsDingbat = "[" + rsDingbatRange + "]";
var rsLower = "[" + rsLowerRange + "]";
var rsMisc = "[^" + rsAstralRange3 + rsBreakRange + rsDigits + rsDingbatRange + rsLowerRange + rsUpperRange + "]";
var rsFitz2 = "\\ud83c[\\udffb-\\udfff]";
var rsModifier2 = "(?:" + rsCombo3 + "|" + rsFitz2 + ")";
var rsNonAstral2 = "[^" + rsAstralRange3 + "]";
var rsRegional2 = "(?:\\ud83c[\\udde6-\\uddff]){2}";
var rsSurrPair2 = "[\\ud800-\\udbff][\\udc00-\\udfff]";
var rsUpper = "[" + rsUpperRange + "]";
var rsZWJ3 = "\\u200d";
var rsMiscLower = "(?:" + rsLower + "|" + rsMisc + ")";
var rsMiscUpper = "(?:" + rsUpper + "|" + rsMisc + ")";
var rsOptContrLower = "(?:" + rsApos + "(?:d|ll|m|re|s|t|ve))?";
var rsOptContrUpper = "(?:" + rsApos + "(?:D|LL|M|RE|S|T|VE))?";
var reOptMod2 = rsModifier2 + "?";
var rsOptVar2 = "[" + rsVarRange3 + "]?";
var rsOptJoin2 = "(?:" + rsZWJ3 + "(?:" + [rsNonAstral2, rsRegional2, rsSurrPair2].join("|") + ")" + rsOptVar2 + reOptMod2 + ")*";
var rsOrdLower = "\\d*(?:1st|2nd|3rd|(?![123])\\dth)(?=\\b|[A-Z_])";
var rsOrdUpper = "\\d*(?:1ST|2ND|3RD|(?![123])\\dTH)(?=\\b|[a-z_])";
var rsSeq2 = rsOptVar2 + reOptMod2 + rsOptJoin2;
var rsEmoji = "(?:" + [rsDingbat, rsRegional2, rsSurrPair2].join("|") + ")" + rsSeq2;
var reUnicodeWord = RegExp([rsUpper + "?" + rsLower + "+" + rsOptContrLower + "(?=" + [rsBreak, rsUpper, "$"].join("|") + ")", rsMiscUpper + "+" + rsOptContrUpper + "(?=" + [rsBreak, rsUpper + rsMiscLower, "$"].join("|") + ")", rsUpper + "?" + rsMiscLower + "+" + rsOptContrLower, rsUpper + "+" + rsOptContrUpper, rsOrdUpper, rsOrdLower, rsDigits, rsEmoji].join("|"), "g");
function unicodeWords(string) {
  return string.match(reUnicodeWord) || [];
}
var unicodeWords_default = unicodeWords;

// node_modules/lodash-es/words.js
function words(string, pattern, guard) {
  string = toString_default(string);
  pattern = guard ? void 0 : pattern;
  if (pattern === void 0) {
    return hasUnicodeWord_default(string) ? unicodeWords_default(string) : asciiWords_default(string);
  }
  return string.match(pattern) || [];
}
var words_default = words;

// node_modules/lodash-es/_createCompounder.js
var rsApos2 = "['’]";
var reApos = RegExp(rsApos2, "g");
function createCompounder(callback) {
  return function(string) {
    return arrayReduce_default(words_default(deburr_default(string).replace(reApos, "")), callback, "");
  };
}
var createCompounder_default = createCompounder;

// node_modules/lodash-es/camelCase.js
var camelCase = createCompounder_default(function(result2, word, index) {
  word = word.toLowerCase();
  return result2 + (index ? capitalize_default(word) : word);
});
var camelCase_default = camelCase;

// node_modules/lodash-es/castArray.js
function castArray() {
  if (!arguments.length) {
    return [];
  }
  var value = arguments[0];
  return isArray_default(value) ? value : [value];
}
var castArray_default = castArray;

// node_modules/lodash-es/_createRound.js
var nativeIsFinite = root_default.isFinite;
var nativeMin3 = Math.min;
function createRound(methodName) {
  var func = Math[methodName];
  return function(number, precision) {
    number = toNumber_default(number);
    precision = precision == null ? 0 : nativeMin3(toInteger_default(precision), 292);
    if (precision && nativeIsFinite(number)) {
      var pair = (toString_default(number) + "e").split("e"), value = func(pair[0] + "e" + (+pair[1] + precision));
      pair = (toString_default(value) + "e").split("e");
      return +(pair[0] + "e" + (+pair[1] - precision));
    }
    return func(number);
  };
}
var createRound_default = createRound;

// node_modules/lodash-es/ceil.js
var ceil = createRound_default("ceil");
var ceil_default = ceil;

// node_modules/lodash-es/chain.js
function chain(value) {
  var result2 = wrapperLodash_default(value);
  result2.__chain__ = true;
  return result2;
}
var chain_default = chain;

// node_modules/lodash-es/chunk.js
var nativeCeil = Math.ceil;
var nativeMax5 = Math.max;
function chunk(array, size2, guard) {
  if (guard ? isIterateeCall_default(array, size2, guard) : size2 === void 0) {
    size2 = 1;
  } else {
    size2 = nativeMax5(toInteger_default(size2), 0);
  }
  var length = array == null ? 0 : array.length;
  if (!length || size2 < 1) {
    return [];
  }
  var index = 0, resIndex = 0, result2 = Array(nativeCeil(length / size2));
  while (index < length) {
    result2[resIndex++] = baseSlice_default(array, index, index += size2);
  }
  return result2;
}
var chunk_default = chunk;

// node_modules/lodash-es/_baseClamp.js
function baseClamp(number, lower, upper) {
  if (number === number) {
    if (upper !== void 0) {
      number = number <= upper ? number : upper;
    }
    if (lower !== void 0) {
      number = number >= lower ? number : lower;
    }
  }
  return number;
}
var baseClamp_default = baseClamp;

// node_modules/lodash-es/clamp.js
function clamp(number, lower, upper) {
  if (upper === void 0) {
    upper = lower;
    lower = void 0;
  }
  if (upper !== void 0) {
    upper = toNumber_default(upper);
    upper = upper === upper ? upper : 0;
  }
  if (lower !== void 0) {
    lower = toNumber_default(lower);
    lower = lower === lower ? lower : 0;
  }
  return baseClamp_default(toNumber_default(number), lower, upper);
}
var clamp_default = clamp;

// node_modules/lodash-es/_stackClear.js
function stackClear() {
  this.__data__ = new ListCache_default();
  this.size = 0;
}
var stackClear_default = stackClear;

// node_modules/lodash-es/_stackDelete.js
function stackDelete(key) {
  var data = this.__data__, result2 = data["delete"](key);
  this.size = data.size;
  return result2;
}
var stackDelete_default = stackDelete;

// node_modules/lodash-es/_stackGet.js
function stackGet(key) {
  return this.__data__.get(key);
}
var stackGet_default = stackGet;

// node_modules/lodash-es/_stackHas.js
function stackHas(key) {
  return this.__data__.has(key);
}
var stackHas_default = stackHas;

// node_modules/lodash-es/_stackSet.js
var LARGE_ARRAY_SIZE = 200;
function stackSet(key, value) {
  var data = this.__data__;
  if (data instanceof ListCache_default) {
    var pairs = data.__data__;
    if (!Map_default || pairs.length < LARGE_ARRAY_SIZE - 1) {
      pairs.push([key, value]);
      this.size = ++data.size;
      return this;
    }
    data = this.__data__ = new MapCache_default(pairs);
  }
  data.set(key, value);
  this.size = data.size;
  return this;
}
var stackSet_default = stackSet;

// node_modules/lodash-es/_Stack.js
function Stack(entries) {
  var data = this.__data__ = new ListCache_default(entries);
  this.size = data.size;
}
Stack.prototype.clear = stackClear_default;
Stack.prototype["delete"] = stackDelete_default;
Stack.prototype.get = stackGet_default;
Stack.prototype.has = stackHas_default;
Stack.prototype.set = stackSet_default;
var Stack_default = Stack;

// node_modules/lodash-es/_baseAssign.js
function baseAssign(object, source) {
  return object && copyObject_default(source, keys_default(source), object);
}
var baseAssign_default = baseAssign;

// node_modules/lodash-es/_baseAssignIn.js
function baseAssignIn(object, source) {
  return object && copyObject_default(source, keysIn_default(source), object);
}
var baseAssignIn_default = baseAssignIn;

// node_modules/lodash-es/_cloneBuffer.js
var freeExports3 = typeof exports == "object" && exports && !exports.nodeType && exports;
var freeModule3 = freeExports3 && typeof module == "object" && module && !module.nodeType && module;
var moduleExports3 = freeModule3 && freeModule3.exports === freeExports3;
var Buffer2 = moduleExports3 ? root_default.Buffer : void 0;
var allocUnsafe = Buffer2 ? Buffer2.allocUnsafe : void 0;
function cloneBuffer(buffer, isDeep) {
  if (isDeep) {
    return buffer.slice();
  }
  var length = buffer.length, result2 = allocUnsafe ? allocUnsafe(length) : new buffer.constructor(length);
  buffer.copy(result2);
  return result2;
}
var cloneBuffer_default = cloneBuffer;

// node_modules/lodash-es/_arrayFilter.js
function arrayFilter(array, predicate) {
  var index = -1, length = array == null ? 0 : array.length, resIndex = 0, result2 = [];
  while (++index < length) {
    var value = array[index];
    if (predicate(value, index, array)) {
      result2[resIndex++] = value;
    }
  }
  return result2;
}
var arrayFilter_default = arrayFilter;

// node_modules/lodash-es/stubArray.js
function stubArray() {
  return [];
}
var stubArray_default = stubArray;

// node_modules/lodash-es/_getSymbols.js
var objectProto16 = Object.prototype;
var propertyIsEnumerable2 = objectProto16.propertyIsEnumerable;
var nativeGetSymbols = Object.getOwnPropertySymbols;
var getSymbols = !nativeGetSymbols ? stubArray_default : function(object) {
  if (object == null) {
    return [];
  }
  object = Object(object);
  return arrayFilter_default(nativeGetSymbols(object), function(symbol) {
    return propertyIsEnumerable2.call(object, symbol);
  });
};
var getSymbols_default = getSymbols;

// node_modules/lodash-es/_copySymbols.js
function copySymbols(source, object) {
  return copyObject_default(source, getSymbols_default(source), object);
}
var copySymbols_default = copySymbols;

// node_modules/lodash-es/_getSymbolsIn.js
var nativeGetSymbols2 = Object.getOwnPropertySymbols;
var getSymbolsIn = !nativeGetSymbols2 ? stubArray_default : function(object) {
  var result2 = [];
  while (object) {
    arrayPush_default(result2, getSymbols_default(object));
    object = getPrototype_default(object);
  }
  return result2;
};
var getSymbolsIn_default = getSymbolsIn;

// node_modules/lodash-es/_copySymbolsIn.js
function copySymbolsIn(source, object) {
  return copyObject_default(source, getSymbolsIn_default(source), object);
}
var copySymbolsIn_default = copySymbolsIn;

// node_modules/lodash-es/_baseGetAllKeys.js
function baseGetAllKeys(object, keysFunc, symbolsFunc) {
  var result2 = keysFunc(object);
  return isArray_default(object) ? result2 : arrayPush_default(result2, symbolsFunc(object));
}
var baseGetAllKeys_default = baseGetAllKeys;

// node_modules/lodash-es/_getAllKeys.js
function getAllKeys(object) {
  return baseGetAllKeys_default(object, keys_default, getSymbols_default);
}
var getAllKeys_default = getAllKeys;

// node_modules/lodash-es/_getAllKeysIn.js
function getAllKeysIn(object) {
  return baseGetAllKeys_default(object, keysIn_default, getSymbolsIn_default);
}
var getAllKeysIn_default = getAllKeysIn;

// node_modules/lodash-es/_DataView.js
var DataView = getNative_default(root_default, "DataView");
var DataView_default = DataView;

// node_modules/lodash-es/_Promise.js
var Promise2 = getNative_default(root_default, "Promise");
var Promise_default = Promise2;

// node_modules/lodash-es/_Set.js
var Set = getNative_default(root_default, "Set");
var Set_default = Set;

// node_modules/lodash-es/_getTag.js
var mapTag2 = "[object Map]";
var objectTag3 = "[object Object]";
var promiseTag = "[object Promise]";
var setTag2 = "[object Set]";
var weakMapTag2 = "[object WeakMap]";
var dataViewTag2 = "[object DataView]";
var dataViewCtorString = toSource_default(DataView_default);
var mapCtorString = toSource_default(Map_default);
var promiseCtorString = toSource_default(Promise_default);
var setCtorString = toSource_default(Set_default);
var weakMapCtorString = toSource_default(WeakMap_default);
var getTag = baseGetTag_default;
if (DataView_default && getTag(new DataView_default(new ArrayBuffer(1))) != dataViewTag2 || Map_default && getTag(new Map_default()) != mapTag2 || Promise_default && getTag(Promise_default.resolve()) != promiseTag || Set_default && getTag(new Set_default()) != setTag2 || WeakMap_default && getTag(new WeakMap_default()) != weakMapTag2) {
  getTag = function(value) {
    var result2 = baseGetTag_default(value), Ctor = result2 == objectTag3 ? value.constructor : void 0, ctorString = Ctor ? toSource_default(Ctor) : "";
    if (ctorString) {
      switch (ctorString) {
        case dataViewCtorString:
          return dataViewTag2;
        case mapCtorString:
          return mapTag2;
        case promiseCtorString:
          return promiseTag;
        case setCtorString:
          return setTag2;
        case weakMapCtorString:
          return weakMapTag2;
      }
    }
    return result2;
  };
}
var getTag_default = getTag;

// node_modules/lodash-es/_initCloneArray.js
var objectProto17 = Object.prototype;
var hasOwnProperty14 = objectProto17.hasOwnProperty;
function initCloneArray(array) {
  var length = array.length, result2 = new array.constructor(length);
  if (length && typeof array[0] == "string" && hasOwnProperty14.call(array, "index")) {
    result2.index = array.index;
    result2.input = array.input;
  }
  return result2;
}
var initCloneArray_default = initCloneArray;

// node_modules/lodash-es/_Uint8Array.js
var Uint8Array = root_default.Uint8Array;
var Uint8Array_default = Uint8Array;

// node_modules/lodash-es/_cloneArrayBuffer.js
function cloneArrayBuffer(arrayBuffer) {
  var result2 = new arrayBuffer.constructor(arrayBuffer.byteLength);
  new Uint8Array_default(result2).set(new Uint8Array_default(arrayBuffer));
  return result2;
}
var cloneArrayBuffer_default = cloneArrayBuffer;

// node_modules/lodash-es/_cloneDataView.js
function cloneDataView(dataView, isDeep) {
  var buffer = isDeep ? cloneArrayBuffer_default(dataView.buffer) : dataView.buffer;
  return new dataView.constructor(buffer, dataView.byteOffset, dataView.byteLength);
}
var cloneDataView_default = cloneDataView;

// node_modules/lodash-es/_cloneRegExp.js
var reFlags = /\w*$/;
function cloneRegExp(regexp) {
  var result2 = new regexp.constructor(regexp.source, reFlags.exec(regexp));
  result2.lastIndex = regexp.lastIndex;
  return result2;
}
var cloneRegExp_default = cloneRegExp;

// node_modules/lodash-es/_cloneSymbol.js
var symbolProto2 = Symbol_default ? Symbol_default.prototype : void 0;
var symbolValueOf = symbolProto2 ? symbolProto2.valueOf : void 0;
function cloneSymbol(symbol) {
  return symbolValueOf ? Object(symbolValueOf.call(symbol)) : {};
}
var cloneSymbol_default = cloneSymbol;

// node_modules/lodash-es/_cloneTypedArray.js
function cloneTypedArray(typedArray, isDeep) {
  var buffer = isDeep ? cloneArrayBuffer_default(typedArray.buffer) : typedArray.buffer;
  return new typedArray.constructor(buffer, typedArray.byteOffset, typedArray.length);
}
var cloneTypedArray_default = cloneTypedArray;

// node_modules/lodash-es/_initCloneByTag.js
var boolTag2 = "[object Boolean]";
var dateTag2 = "[object Date]";
var mapTag3 = "[object Map]";
var numberTag2 = "[object Number]";
var regexpTag2 = "[object RegExp]";
var setTag3 = "[object Set]";
var stringTag2 = "[object String]";
var symbolTag2 = "[object Symbol]";
var arrayBufferTag2 = "[object ArrayBuffer]";
var dataViewTag3 = "[object DataView]";
var float32Tag2 = "[object Float32Array]";
var float64Tag2 = "[object Float64Array]";
var int8Tag2 = "[object Int8Array]";
var int16Tag2 = "[object Int16Array]";
var int32Tag2 = "[object Int32Array]";
var uint8Tag2 = "[object Uint8Array]";
var uint8ClampedTag2 = "[object Uint8ClampedArray]";
var uint16Tag2 = "[object Uint16Array]";
var uint32Tag2 = "[object Uint32Array]";
function initCloneByTag(object, tag, isDeep) {
  var Ctor = object.constructor;
  switch (tag) {
    case arrayBufferTag2:
      return cloneArrayBuffer_default(object);
    case boolTag2:
    case dateTag2:
      return new Ctor(+object);
    case dataViewTag3:
      return cloneDataView_default(object, isDeep);
    case float32Tag2:
    case float64Tag2:
    case int8Tag2:
    case int16Tag2:
    case int32Tag2:
    case uint8Tag2:
    case uint8ClampedTag2:
    case uint16Tag2:
    case uint32Tag2:
      return cloneTypedArray_default(object, isDeep);
    case mapTag3:
      return new Ctor();
    case numberTag2:
    case stringTag2:
      return new Ctor(object);
    case regexpTag2:
      return cloneRegExp_default(object);
    case setTag3:
      return new Ctor();
    case symbolTag2:
      return cloneSymbol_default(object);
  }
}
var initCloneByTag_default = initCloneByTag;

// node_modules/lodash-es/_initCloneObject.js
function initCloneObject(object) {
  return typeof object.constructor == "function" && !isPrototype_default(object) ? baseCreate_default(getPrototype_default(object)) : {};
}
var initCloneObject_default = initCloneObject;

// node_modules/lodash-es/_baseIsMap.js
var mapTag4 = "[object Map]";
function baseIsMap(value) {
  return isObjectLike_default(value) && getTag_default(value) == mapTag4;
}
var baseIsMap_default = baseIsMap;

// node_modules/lodash-es/isMap.js
var nodeIsMap = nodeUtil_default && nodeUtil_default.isMap;
var isMap = nodeIsMap ? baseUnary_default(nodeIsMap) : baseIsMap_default;
var isMap_default = isMap;

// node_modules/lodash-es/_baseIsSet.js
var setTag4 = "[object Set]";
function baseIsSet(value) {
  return isObjectLike_default(value) && getTag_default(value) == setTag4;
}
var baseIsSet_default = baseIsSet;

// node_modules/lodash-es/isSet.js
var nodeIsSet = nodeUtil_default && nodeUtil_default.isSet;
var isSet = nodeIsSet ? baseUnary_default(nodeIsSet) : baseIsSet_default;
var isSet_default = isSet;

// node_modules/lodash-es/_baseClone.js
var CLONE_DEEP_FLAG = 1;
var CLONE_FLAT_FLAG = 2;
var CLONE_SYMBOLS_FLAG = 4;
var argsTag3 = "[object Arguments]";
var arrayTag2 = "[object Array]";
var boolTag3 = "[object Boolean]";
var dateTag3 = "[object Date]";
var errorTag3 = "[object Error]";
var funcTag3 = "[object Function]";
var genTag2 = "[object GeneratorFunction]";
var mapTag5 = "[object Map]";
var numberTag3 = "[object Number]";
var objectTag4 = "[object Object]";
var regexpTag3 = "[object RegExp]";
var setTag5 = "[object Set]";
var stringTag3 = "[object String]";
var symbolTag3 = "[object Symbol]";
var weakMapTag3 = "[object WeakMap]";
var arrayBufferTag3 = "[object ArrayBuffer]";
var dataViewTag4 = "[object DataView]";
var float32Tag3 = "[object Float32Array]";
var float64Tag3 = "[object Float64Array]";
var int8Tag3 = "[object Int8Array]";
var int16Tag3 = "[object Int16Array]";
var int32Tag3 = "[object Int32Array]";
var uint8Tag3 = "[object Uint8Array]";
var uint8ClampedTag3 = "[object Uint8ClampedArray]";
var uint16Tag3 = "[object Uint16Array]";
var uint32Tag3 = "[object Uint32Array]";
var cloneableTags = {};
cloneableTags[argsTag3] = cloneableTags[arrayTag2] = cloneableTags[arrayBufferTag3] = cloneableTags[dataViewTag4] = cloneableTags[boolTag3] = cloneableTags[dateTag3] = cloneableTags[float32Tag3] = cloneableTags[float64Tag3] = cloneableTags[int8Tag3] = cloneableTags[int16Tag3] = cloneableTags[int32Tag3] = cloneableTags[mapTag5] = cloneableTags[numberTag3] = cloneableTags[objectTag4] = cloneableTags[regexpTag3] = cloneableTags[setTag5] = cloneableTags[stringTag3] = cloneableTags[symbolTag3] = cloneableTags[uint8Tag3] = cloneableTags[uint8ClampedTag3] = cloneableTags[uint16Tag3] = cloneableTags[uint32Tag3] = true;
cloneableTags[errorTag3] = cloneableTags[funcTag3] = cloneableTags[weakMapTag3] = false;
function baseClone(value, bitmask, customizer, key, object, stack) {
  var result2, isDeep = bitmask & CLONE_DEEP_FLAG, isFlat = bitmask & CLONE_FLAT_FLAG, isFull = bitmask & CLONE_SYMBOLS_FLAG;
  if (customizer) {
    result2 = object ? customizer(value, key, object, stack) : customizer(value);
  }
  if (result2 !== void 0) {
    return result2;
  }
  if (!isObject_default(value)) {
    return value;
  }
  var isArr = isArray_default(value);
  if (isArr) {
    result2 = initCloneArray_default(value);
    if (!isDeep) {
      return copyArray_default(value, result2);
    }
  } else {
    var tag = getTag_default(value), isFunc = tag == funcTag3 || tag == genTag2;
    if (isBuffer_default(value)) {
      return cloneBuffer_default(value, isDeep);
    }
    if (tag == objectTag4 || tag == argsTag3 || isFunc && !object) {
      result2 = isFlat || isFunc ? {} : initCloneObject_default(value);
      if (!isDeep) {
        return isFlat ? copySymbolsIn_default(value, baseAssignIn_default(result2, value)) : copySymbols_default(value, baseAssign_default(result2, value));
      }
    } else {
      if (!cloneableTags[tag]) {
        return object ? value : {};
      }
      result2 = initCloneByTag_default(value, tag, isDeep);
    }
  }
  stack || (stack = new Stack_default());
  var stacked = stack.get(value);
  if (stacked) {
    return stacked;
  }
  stack.set(value, result2);
  if (isSet_default(value)) {
    value.forEach(function(subValue) {
      result2.add(baseClone(subValue, bitmask, customizer, subValue, value, stack));
    });
  } else if (isMap_default(value)) {
    value.forEach(function(subValue, key2) {
      result2.set(key2, baseClone(subValue, bitmask, customizer, key2, value, stack));
    });
  }
  var keysFunc = isFull ? isFlat ? getAllKeysIn_default : getAllKeys_default : isFlat ? keysIn_default : keys_default;
  var props = isArr ? void 0 : keysFunc(value);
  arrayEach_default(props || value, function(subValue, key2) {
    if (props) {
      key2 = subValue;
      subValue = value[key2];
    }
    assignValue_default(result2, key2, baseClone(subValue, bitmask, customizer, key2, value, stack));
  });
  return result2;
}
var baseClone_default = baseClone;

// node_modules/lodash-es/clone.js
var CLONE_SYMBOLS_FLAG2 = 4;
function clone(value) {
  return baseClone_default(value, CLONE_SYMBOLS_FLAG2);
}
var clone_default = clone;

// node_modules/lodash-es/cloneDeep.js
var CLONE_DEEP_FLAG2 = 1;
var CLONE_SYMBOLS_FLAG3 = 4;
function cloneDeep(value) {
  return baseClone_default(value, CLONE_DEEP_FLAG2 | CLONE_SYMBOLS_FLAG3);
}
var cloneDeep_default = cloneDeep;

// node_modules/lodash-es/cloneDeepWith.js
var CLONE_DEEP_FLAG3 = 1;
var CLONE_SYMBOLS_FLAG4 = 4;
function cloneDeepWith(value, customizer) {
  customizer = typeof customizer == "function" ? customizer : void 0;
  return baseClone_default(value, CLONE_DEEP_FLAG3 | CLONE_SYMBOLS_FLAG4, customizer);
}
var cloneDeepWith_default = cloneDeepWith;

// node_modules/lodash-es/cloneWith.js
var CLONE_SYMBOLS_FLAG5 = 4;
function cloneWith(value, customizer) {
  customizer = typeof customizer == "function" ? customizer : void 0;
  return baseClone_default(value, CLONE_SYMBOLS_FLAG5, customizer);
}
var cloneWith_default = cloneWith;

// node_modules/lodash-es/commit.js
function wrapperCommit() {
  return new LodashWrapper_default(this.value(), this.__chain__);
}
var commit_default = wrapperCommit;

// node_modules/lodash-es/compact.js
function compact(array) {
  var index = -1, length = array == null ? 0 : array.length, resIndex = 0, result2 = [];
  while (++index < length) {
    var value = array[index];
    if (value) {
      result2[resIndex++] = value;
    }
  }
  return result2;
}
var compact_default = compact;

// node_modules/lodash-es/concat.js
function concat() {
  var length = arguments.length;
  if (!length) {
    return [];
  }
  var args = Array(length - 1), array = arguments[0], index = length;
  while (index--) {
    args[index - 1] = arguments[index];
  }
  return arrayPush_default(isArray_default(array) ? copyArray_default(array) : [array], baseFlatten_default(args, 1));
}
var concat_default = concat;

// node_modules/lodash-es/_setCacheAdd.js
var HASH_UNDEFINED3 = "__lodash_hash_undefined__";
function setCacheAdd(value) {
  this.__data__.set(value, HASH_UNDEFINED3);
  return this;
}
var setCacheAdd_default = setCacheAdd;

// node_modules/lodash-es/_setCacheHas.js
function setCacheHas(value) {
  return this.__data__.has(value);
}
var setCacheHas_default = setCacheHas;

// node_modules/lodash-es/_SetCache.js
function SetCache(values2) {
  var index = -1, length = values2 == null ? 0 : values2.length;
  this.__data__ = new MapCache_default();
  while (++index < length) {
    this.add(values2[index]);
  }
}
SetCache.prototype.add = SetCache.prototype.push = setCacheAdd_default;
SetCache.prototype.has = setCacheHas_default;
var SetCache_default = SetCache;

// node_modules/lodash-es/_arraySome.js
function arraySome(array, predicate) {
  var index = -1, length = array == null ? 0 : array.length;
  while (++index < length) {
    if (predicate(array[index], index, array)) {
      return true;
    }
  }
  return false;
}
var arraySome_default = arraySome;

// node_modules/lodash-es/_cacheHas.js
function cacheHas(cache, key) {
  return cache.has(key);
}
var cacheHas_default = cacheHas;

// node_modules/lodash-es/_equalArrays.js
var COMPARE_PARTIAL_FLAG = 1;
var COMPARE_UNORDERED_FLAG = 2;
function equalArrays(array, other, bitmask, customizer, equalFunc, stack) {
  var isPartial = bitmask & COMPARE_PARTIAL_FLAG, arrLength = array.length, othLength = other.length;
  if (arrLength != othLength && !(isPartial && othLength > arrLength)) {
    return false;
  }
  var arrStacked = stack.get(array);
  var othStacked = stack.get(other);
  if (arrStacked && othStacked) {
    return arrStacked == other && othStacked == array;
  }
  var index = -1, result2 = true, seen = bitmask & COMPARE_UNORDERED_FLAG ? new SetCache_default() : void 0;
  stack.set(array, other);
  stack.set(other, array);
  while (++index < arrLength) {
    var arrValue = array[index], othValue = other[index];
    if (customizer) {
      var compared = isPartial ? customizer(othValue, arrValue, index, other, array, stack) : customizer(arrValue, othValue, index, array, other, stack);
    }
    if (compared !== void 0) {
      if (compared) {
        continue;
      }
      result2 = false;
      break;
    }
    if (seen) {
      if (!arraySome_default(other, function(othValue2, othIndex) {
        if (!cacheHas_default(seen, othIndex) && (arrValue === othValue2 || equalFunc(arrValue, othValue2, bitmask, customizer, stack))) {
          return seen.push(othIndex);
        }
      })) {
        result2 = false;
        break;
      }
    } else if (!(arrValue === othValue || equalFunc(arrValue, othValue, bitmask, customizer, stack))) {
      result2 = false;
      break;
    }
  }
  stack["delete"](array);
  stack["delete"](other);
  return result2;
}
var equalArrays_default = equalArrays;

// node_modules/lodash-es/_mapToArray.js
function mapToArray(map2) {
  var index = -1, result2 = Array(map2.size);
  map2.forEach(function(value, key) {
    result2[++index] = [key, value];
  });
  return result2;
}
var mapToArray_default = mapToArray;

// node_modules/lodash-es/_setToArray.js
function setToArray(set2) {
  var index = -1, result2 = Array(set2.size);
  set2.forEach(function(value) {
    result2[++index] = value;
  });
  return result2;
}
var setToArray_default = setToArray;

// node_modules/lodash-es/_equalByTag.js
var COMPARE_PARTIAL_FLAG2 = 1;
var COMPARE_UNORDERED_FLAG2 = 2;
var boolTag4 = "[object Boolean]";
var dateTag4 = "[object Date]";
var errorTag4 = "[object Error]";
var mapTag6 = "[object Map]";
var numberTag4 = "[object Number]";
var regexpTag4 = "[object RegExp]";
var setTag6 = "[object Set]";
var stringTag4 = "[object String]";
var symbolTag4 = "[object Symbol]";
var arrayBufferTag4 = "[object ArrayBuffer]";
var dataViewTag5 = "[object DataView]";
var symbolProto3 = Symbol_default ? Symbol_default.prototype : void 0;
var symbolValueOf2 = symbolProto3 ? symbolProto3.valueOf : void 0;
function equalByTag(object, other, tag, bitmask, customizer, equalFunc, stack) {
  switch (tag) {
    case dataViewTag5:
      if (object.byteLength != other.byteLength || object.byteOffset != other.byteOffset) {
        return false;
      }
      object = object.buffer;
      other = other.buffer;
    case arrayBufferTag4:
      if (object.byteLength != other.byteLength || !equalFunc(new Uint8Array_default(object), new Uint8Array_default(other))) {
        return false;
      }
      return true;
    case boolTag4:
    case dateTag4:
    case numberTag4:
      return eq_default(+object, +other);
    case errorTag4:
      return object.name == other.name && object.message == other.message;
    case regexpTag4:
    case stringTag4:
      return object == other + "";
    case mapTag6:
      var convert = mapToArray_default;
    case setTag6:
      var isPartial = bitmask & COMPARE_PARTIAL_FLAG2;
      convert || (convert = setToArray_default);
      if (object.size != other.size && !isPartial) {
        return false;
      }
      var stacked = stack.get(object);
      if (stacked) {
        return stacked == other;
      }
      bitmask |= COMPARE_UNORDERED_FLAG2;
      stack.set(object, other);
      var result2 = equalArrays_default(convert(object), convert(other), bitmask, customizer, equalFunc, stack);
      stack["delete"](object);
      return result2;
    case symbolTag4:
      if (symbolValueOf2) {
        return symbolValueOf2.call(object) == symbolValueOf2.call(other);
      }
  }
  return false;
}
var equalByTag_default = equalByTag;

// node_modules/lodash-es/_equalObjects.js
var COMPARE_PARTIAL_FLAG3 = 1;
var objectProto18 = Object.prototype;
var hasOwnProperty15 = objectProto18.hasOwnProperty;
function equalObjects(object, other, bitmask, customizer, equalFunc, stack) {
  var isPartial = bitmask & COMPARE_PARTIAL_FLAG3, objProps = getAllKeys_default(object), objLength = objProps.length, othProps = getAllKeys_default(other), othLength = othProps.length;
  if (objLength != othLength && !isPartial) {
    return false;
  }
  var index = objLength;
  while (index--) {
    var key = objProps[index];
    if (!(isPartial ? key in other : hasOwnProperty15.call(other, key))) {
      return false;
    }
  }
  var objStacked = stack.get(object);
  var othStacked = stack.get(other);
  if (objStacked && othStacked) {
    return objStacked == other && othStacked == object;
  }
  var result2 = true;
  stack.set(object, other);
  stack.set(other, object);
  var skipCtor = isPartial;
  while (++index < objLength) {
    key = objProps[index];
    var objValue = object[key], othValue = other[key];
    if (customizer) {
      var compared = isPartial ? customizer(othValue, objValue, key, other, object, stack) : customizer(objValue, othValue, key, object, other, stack);
    }
    if (!(compared === void 0 ? objValue === othValue || equalFunc(objValue, othValue, bitmask, customizer, stack) : compared)) {
      result2 = false;
      break;
    }
    skipCtor || (skipCtor = key == "constructor");
  }
  if (result2 && !skipCtor) {
    var objCtor = object.constructor, othCtor = other.constructor;
    if (objCtor != othCtor && "constructor" in object && "constructor" in other && !(typeof objCtor == "function" && objCtor instanceof objCtor && typeof othCtor == "function" && othCtor instanceof othCtor)) {
      result2 = false;
    }
  }
  stack["delete"](object);
  stack["delete"](other);
  return result2;
}
var equalObjects_default = equalObjects;

// node_modules/lodash-es/_baseIsEqualDeep.js
var COMPARE_PARTIAL_FLAG4 = 1;
var argsTag4 = "[object Arguments]";
var arrayTag3 = "[object Array]";
var objectTag5 = "[object Object]";
var objectProto19 = Object.prototype;
var hasOwnProperty16 = objectProto19.hasOwnProperty;
function baseIsEqualDeep(object, other, bitmask, customizer, equalFunc, stack) {
  var objIsArr = isArray_default(object), othIsArr = isArray_default(other), objTag = objIsArr ? arrayTag3 : getTag_default(object), othTag = othIsArr ? arrayTag3 : getTag_default(other);
  objTag = objTag == argsTag4 ? objectTag5 : objTag;
  othTag = othTag == argsTag4 ? objectTag5 : othTag;
  var objIsObj = objTag == objectTag5, othIsObj = othTag == objectTag5, isSameTag = objTag == othTag;
  if (isSameTag && isBuffer_default(object)) {
    if (!isBuffer_default(other)) {
      return false;
    }
    objIsArr = true;
    objIsObj = false;
  }
  if (isSameTag && !objIsObj) {
    stack || (stack = new Stack_default());
    return objIsArr || isTypedArray_default(object) ? equalArrays_default(object, other, bitmask, customizer, equalFunc, stack) : equalByTag_default(object, other, objTag, bitmask, customizer, equalFunc, stack);
  }
  if (!(bitmask & COMPARE_PARTIAL_FLAG4)) {
    var objIsWrapped = objIsObj && hasOwnProperty16.call(object, "__wrapped__"), othIsWrapped = othIsObj && hasOwnProperty16.call(other, "__wrapped__");
    if (objIsWrapped || othIsWrapped) {
      var objUnwrapped = objIsWrapped ? object.value() : object, othUnwrapped = othIsWrapped ? other.value() : other;
      stack || (stack = new Stack_default());
      return equalFunc(objUnwrapped, othUnwrapped, bitmask, customizer, stack);
    }
  }
  if (!isSameTag) {
    return false;
  }
  stack || (stack = new Stack_default());
  return equalObjects_default(object, other, bitmask, customizer, equalFunc, stack);
}
var baseIsEqualDeep_default = baseIsEqualDeep;

// node_modules/lodash-es/_baseIsEqual.js
function baseIsEqual(value, other, bitmask, customizer, stack) {
  if (value === other) {
    return true;
  }
  if (value == null || other == null || !isObjectLike_default(value) && !isObjectLike_default(other)) {
    return value !== value && other !== other;
  }
  return baseIsEqualDeep_default(value, other, bitmask, customizer, baseIsEqual, stack);
}
var baseIsEqual_default = baseIsEqual;

// node_modules/lodash-es/_baseIsMatch.js
var COMPARE_PARTIAL_FLAG5 = 1;
var COMPARE_UNORDERED_FLAG3 = 2;
function baseIsMatch(object, source, matchData, customizer) {
  var index = matchData.length, length = index, noCustomizer = !customizer;
  if (object == null) {
    return !length;
  }
  object = Object(object);
  while (index--) {
    var data = matchData[index];
    if (noCustomizer && data[2] ? data[1] !== object[data[0]] : !(data[0] in object)) {
      return false;
    }
  }
  while (++index < length) {
    data = matchData[index];
    var key = data[0], objValue = object[key], srcValue = data[1];
    if (noCustomizer && data[2]) {
      if (objValue === void 0 && !(key in object)) {
        return false;
      }
    } else {
      var stack = new Stack_default();
      if (customizer) {
        var result2 = customizer(objValue, srcValue, key, object, source, stack);
      }
      if (!(result2 === void 0 ? baseIsEqual_default(srcValue, objValue, COMPARE_PARTIAL_FLAG5 | COMPARE_UNORDERED_FLAG3, customizer, stack) : result2)) {
        return false;
      }
    }
  }
  return true;
}
var baseIsMatch_default = baseIsMatch;

// node_modules/lodash-es/_isStrictComparable.js
function isStrictComparable(value) {
  return value === value && !isObject_default(value);
}
var isStrictComparable_default = isStrictComparable;

// node_modules/lodash-es/_getMatchData.js
function getMatchData(object) {
  var result2 = keys_default(object), length = result2.length;
  while (length--) {
    var key = result2[length], value = object[key];
    result2[length] = [key, value, isStrictComparable_default(value)];
  }
  return result2;
}
var getMatchData_default = getMatchData;

// node_modules/lodash-es/_matchesStrictComparable.js
function matchesStrictComparable(key, srcValue) {
  return function(object) {
    if (object == null) {
      return false;
    }
    return object[key] === srcValue && (srcValue !== void 0 || key in Object(object));
  };
}
var matchesStrictComparable_default = matchesStrictComparable;

// node_modules/lodash-es/_baseMatches.js
function baseMatches(source) {
  var matchData = getMatchData_default(source);
  if (matchData.length == 1 && matchData[0][2]) {
    return matchesStrictComparable_default(matchData[0][0], matchData[0][1]);
  }
  return function(object) {
    return object === source || baseIsMatch_default(object, source, matchData);
  };
}
var baseMatches_default = baseMatches;

// node_modules/lodash-es/_baseHasIn.js
function baseHasIn(object, key) {
  return object != null && key in Object(object);
}
var baseHasIn_default = baseHasIn;

// node_modules/lodash-es/_hasPath.js
function hasPath(object, path, hasFunc) {
  path = castPath_default(path, object);
  var index = -1, length = path.length, result2 = false;
  while (++index < length) {
    var key = toKey_default(path[index]);
    if (!(result2 = object != null && hasFunc(object, key))) {
      break;
    }
    object = object[key];
  }
  if (result2 || ++index != length) {
    return result2;
  }
  length = object == null ? 0 : object.length;
  return !!length && isLength_default(length) && isIndex_default(key, length) && (isArray_default(object) || isArguments_default(object));
}
var hasPath_default = hasPath;

// node_modules/lodash-es/hasIn.js
function hasIn(object, path) {
  return object != null && hasPath_default(object, path, baseHasIn_default);
}
var hasIn_default = hasIn;

// node_modules/lodash-es/_baseMatchesProperty.js
var COMPARE_PARTIAL_FLAG6 = 1;
var COMPARE_UNORDERED_FLAG4 = 2;
function baseMatchesProperty(path, srcValue) {
  if (isKey_default(path) && isStrictComparable_default(srcValue)) {
    return matchesStrictComparable_default(toKey_default(path), srcValue);
  }
  return function(object) {
    var objValue = get_default(object, path);
    return objValue === void 0 && objValue === srcValue ? hasIn_default(object, path) : baseIsEqual_default(srcValue, objValue, COMPARE_PARTIAL_FLAG6 | COMPARE_UNORDERED_FLAG4);
  };
}
var baseMatchesProperty_default = baseMatchesProperty;

// node_modules/lodash-es/_baseProperty.js
function baseProperty(key) {
  return function(object) {
    return object == null ? void 0 : object[key];
  };
}
var baseProperty_default = baseProperty;

// node_modules/lodash-es/_basePropertyDeep.js
function basePropertyDeep(path) {
  return function(object) {
    return baseGet_default(object, path);
  };
}
var basePropertyDeep_default = basePropertyDeep;

// node_modules/lodash-es/property.js
function property(path) {
  return isKey_default(path) ? baseProperty_default(toKey_default(path)) : basePropertyDeep_default(path);
}
var property_default = property;

// node_modules/lodash-es/_baseIteratee.js
function baseIteratee(value) {
  if (typeof value == "function") {
    return value;
  }
  if (value == null) {
    return identity_default;
  }
  if (typeof value == "object") {
    return isArray_default(value) ? baseMatchesProperty_default(value[0], value[1]) : baseMatches_default(value);
  }
  return property_default(value);
}
var baseIteratee_default = baseIteratee;

// node_modules/lodash-es/cond.js
var FUNC_ERROR_TEXT5 = "Expected a function";
function cond(pairs) {
  var length = pairs == null ? 0 : pairs.length, toIteratee = baseIteratee_default;
  pairs = !length ? [] : arrayMap_default(pairs, function(pair) {
    if (typeof pair[1] != "function") {
      throw new TypeError(FUNC_ERROR_TEXT5);
    }
    return [toIteratee(pair[0]), pair[1]];
  });
  return baseRest_default(function(args) {
    var index = -1;
    while (++index < length) {
      var pair = pairs[index];
      if (apply_default(pair[0], this, args)) {
        return apply_default(pair[1], this, args);
      }
    }
  });
}
var cond_default = cond;

// node_modules/lodash-es/_baseConformsTo.js
function baseConformsTo(object, source, props) {
  var length = props.length;
  if (object == null) {
    return !length;
  }
  object = Object(object);
  while (length--) {
    var key = props[length], predicate = source[key], value = object[key];
    if (value === void 0 && !(key in object) || !predicate(value)) {
      return false;
    }
  }
  return true;
}
var baseConformsTo_default = baseConformsTo;

// node_modules/lodash-es/_baseConforms.js
function baseConforms(source) {
  var props = keys_default(source);
  return function(object) {
    return baseConformsTo_default(object, source, props);
  };
}
var baseConforms_default = baseConforms;

// node_modules/lodash-es/conforms.js
var CLONE_DEEP_FLAG4 = 1;
function conforms(source) {
  return baseConforms_default(baseClone_default(source, CLONE_DEEP_FLAG4));
}
var conforms_default = conforms;

// node_modules/lodash-es/conformsTo.js
function conformsTo(object, source) {
  return source == null || baseConformsTo_default(object, source, keys_default(source));
}
var conformsTo_default = conformsTo;

// node_modules/lodash-es/_arrayAggregator.js
function arrayAggregator(array, setter, iteratee2, accumulator) {
  var index = -1, length = array == null ? 0 : array.length;
  while (++index < length) {
    var value = array[index];
    setter(accumulator, value, iteratee2(value), array);
  }
  return accumulator;
}
var arrayAggregator_default = arrayAggregator;

// node_modules/lodash-es/_createBaseFor.js
function createBaseFor(fromRight) {
  return function(object, iteratee2, keysFunc) {
    var index = -1, iterable = Object(object), props = keysFunc(object), length = props.length;
    while (length--) {
      var key = props[fromRight ? length : ++index];
      if (iteratee2(iterable[key], key, iterable) === false) {
        break;
      }
    }
    return object;
  };
}
var createBaseFor_default = createBaseFor;

// node_modules/lodash-es/_baseFor.js
var baseFor = createBaseFor_default();
var baseFor_default = baseFor;

// node_modules/lodash-es/_baseForOwn.js
function baseForOwn(object, iteratee2) {
  return object && baseFor_default(object, iteratee2, keys_default);
}
var baseForOwn_default = baseForOwn;

// node_modules/lodash-es/_createBaseEach.js
function createBaseEach(eachFunc, fromRight) {
  return function(collection, iteratee2) {
    if (collection == null) {
      return collection;
    }
    if (!isArrayLike_default(collection)) {
      return eachFunc(collection, iteratee2);
    }
    var length = collection.length, index = fromRight ? length : -1, iterable = Object(collection);
    while (fromRight ? index-- : ++index < length) {
      if (iteratee2(iterable[index], index, iterable) === false) {
        break;
      }
    }
    return collection;
  };
}
var createBaseEach_default = createBaseEach;

// node_modules/lodash-es/_baseEach.js
var baseEach = createBaseEach_default(baseForOwn_default);
var baseEach_default = baseEach;

// node_modules/lodash-es/_baseAggregator.js
function baseAggregator(collection, setter, iteratee2, accumulator) {
  baseEach_default(collection, function(value, key, collection2) {
    setter(accumulator, value, iteratee2(value), collection2);
  });
  return accumulator;
}
var baseAggregator_default = baseAggregator;

// node_modules/lodash-es/_createAggregator.js
function createAggregator(setter, initializer) {
  return function(collection, iteratee2) {
    var func = isArray_default(collection) ? arrayAggregator_default : baseAggregator_default, accumulator = initializer ? initializer() : {};
    return func(collection, setter, baseIteratee_default(iteratee2, 2), accumulator);
  };
}
var createAggregator_default = createAggregator;

// node_modules/lodash-es/countBy.js
var objectProto20 = Object.prototype;
var hasOwnProperty17 = objectProto20.hasOwnProperty;
var countBy = createAggregator_default(function(result2, value, key) {
  if (hasOwnProperty17.call(result2, key)) {
    ++result2[key];
  } else {
    baseAssignValue_default(result2, key, 1);
  }
});
var countBy_default = countBy;

// node_modules/lodash-es/create.js
function create(prototype, properties) {
  var result2 = baseCreate_default(prototype);
  return properties == null ? result2 : baseAssign_default(result2, properties);
}
var create_default = create;

// node_modules/lodash-es/curry.js
var WRAP_CURRY_FLAG6 = 8;
function curry(func, arity, guard) {
  arity = guard ? void 0 : arity;
  var result2 = createWrap_default(func, WRAP_CURRY_FLAG6, void 0, void 0, void 0, void 0, void 0, arity);
  result2.placeholder = curry.placeholder;
  return result2;
}
curry.placeholder = {};
var curry_default = curry;

// node_modules/lodash-es/curryRight.js
var WRAP_CURRY_RIGHT_FLAG4 = 16;
function curryRight(func, arity, guard) {
  arity = guard ? void 0 : arity;
  var result2 = createWrap_default(func, WRAP_CURRY_RIGHT_FLAG4, void 0, void 0, void 0, void 0, void 0, arity);
  result2.placeholder = curryRight.placeholder;
  return result2;
}
curryRight.placeholder = {};
var curryRight_default = curryRight;

// node_modules/lodash-es/now.js
var now = function() {
  return root_default.Date.now();
};
var now_default = now;

// node_modules/lodash-es/debounce.js
var FUNC_ERROR_TEXT6 = "Expected a function";
var nativeMax6 = Math.max;
var nativeMin4 = Math.min;
function debounce(func, wait, options) {
  var lastArgs, lastThis, maxWait, result2, timerId, lastCallTime, lastInvokeTime = 0, leading = false, maxing = false, trailing = true;
  if (typeof func != "function") {
    throw new TypeError(FUNC_ERROR_TEXT6);
  }
  wait = toNumber_default(wait) || 0;
  if (isObject_default(options)) {
    leading = !!options.leading;
    maxing = "maxWait" in options;
    maxWait = maxing ? nativeMax6(toNumber_default(options.maxWait) || 0, wait) : maxWait;
    trailing = "trailing" in options ? !!options.trailing : trailing;
  }
  function invokeFunc(time) {
    var args = lastArgs, thisArg = lastThis;
    lastArgs = lastThis = void 0;
    lastInvokeTime = time;
    result2 = func.apply(thisArg, args);
    return result2;
  }
  function leadingEdge(time) {
    lastInvokeTime = time;
    timerId = setTimeout(timerExpired, wait);
    return leading ? invokeFunc(time) : result2;
  }
  function remainingWait(time) {
    var timeSinceLastCall = time - lastCallTime, timeSinceLastInvoke = time - lastInvokeTime, timeWaiting = wait - timeSinceLastCall;
    return maxing ? nativeMin4(timeWaiting, maxWait - timeSinceLastInvoke) : timeWaiting;
  }
  function shouldInvoke(time) {
    var timeSinceLastCall = time - lastCallTime, timeSinceLastInvoke = time - lastInvokeTime;
    return lastCallTime === void 0 || timeSinceLastCall >= wait || timeSinceLastCall < 0 || maxing && timeSinceLastInvoke >= maxWait;
  }
  function timerExpired() {
    var time = now_default();
    if (shouldInvoke(time)) {
      return trailingEdge(time);
    }
    timerId = setTimeout(timerExpired, remainingWait(time));
  }
  function trailingEdge(time) {
    timerId = void 0;
    if (trailing && lastArgs) {
      return invokeFunc(time);
    }
    lastArgs = lastThis = void 0;
    return result2;
  }
  function cancel() {
    if (timerId !== void 0) {
      clearTimeout(timerId);
    }
    lastInvokeTime = 0;
    lastArgs = lastCallTime = lastThis = timerId = void 0;
  }
  function flush() {
    return timerId === void 0 ? result2 : trailingEdge(now_default());
  }
  function debounced() {
    var time = now_default(), isInvoking = shouldInvoke(time);
    lastArgs = arguments;
    lastThis = this;
    lastCallTime = time;
    if (isInvoking) {
      if (timerId === void 0) {
        return leadingEdge(lastCallTime);
      }
      if (maxing) {
        clearTimeout(timerId);
        timerId = setTimeout(timerExpired, wait);
        return invokeFunc(lastCallTime);
      }
    }
    if (timerId === void 0) {
      timerId = setTimeout(timerExpired, wait);
    }
    return result2;
  }
  debounced.cancel = cancel;
  debounced.flush = flush;
  return debounced;
}
var debounce_default = debounce;

// node_modules/lodash-es/defaultTo.js
function defaultTo(value, defaultValue) {
  return value == null || value !== value ? defaultValue : value;
}
var defaultTo_default = defaultTo;

// node_modules/lodash-es/defaults.js
var objectProto21 = Object.prototype;
var hasOwnProperty18 = objectProto21.hasOwnProperty;
var defaults = baseRest_default(function(object, sources) {
  object = Object(object);
  var index = -1;
  var length = sources.length;
  var guard = length > 2 ? sources[2] : void 0;
  if (guard && isIterateeCall_default(sources[0], sources[1], guard)) {
    length = 1;
  }
  while (++index < length) {
    var source = sources[index];
    var props = keysIn_default(source);
    var propsIndex = -1;
    var propsLength = props.length;
    while (++propsIndex < propsLength) {
      var key = props[propsIndex];
      var value = object[key];
      if (value === void 0 || eq_default(value, objectProto21[key]) && !hasOwnProperty18.call(object, key)) {
        object[key] = source[key];
      }
    }
  }
  return object;
});
var defaults_default = defaults;

// node_modules/lodash-es/_assignMergeValue.js
function assignMergeValue(object, key, value) {
  if (value !== void 0 && !eq_default(object[key], value) || value === void 0 && !(key in object)) {
    baseAssignValue_default(object, key, value);
  }
}
var assignMergeValue_default = assignMergeValue;

// node_modules/lodash-es/isArrayLikeObject.js
function isArrayLikeObject(value) {
  return isObjectLike_default(value) && isArrayLike_default(value);
}
var isArrayLikeObject_default = isArrayLikeObject;

// node_modules/lodash-es/_safeGet.js
function safeGet(object, key) {
  if (key === "constructor" && typeof object[key] === "function") {
    return;
  }
  if (key == "__proto__") {
    return;
  }
  return object[key];
}
var safeGet_default = safeGet;

// node_modules/lodash-es/toPlainObject.js
function toPlainObject(value) {
  return copyObject_default(value, keysIn_default(value));
}
var toPlainObject_default = toPlainObject;

// node_modules/lodash-es/_baseMergeDeep.js
function baseMergeDeep(object, source, key, srcIndex, mergeFunc, customizer, stack) {
  var objValue = safeGet_default(object, key), srcValue = safeGet_default(source, key), stacked = stack.get(srcValue);
  if (stacked) {
    assignMergeValue_default(object, key, stacked);
    return;
  }
  var newValue = customizer ? customizer(objValue, srcValue, key + "", object, source, stack) : void 0;
  var isCommon = newValue === void 0;
  if (isCommon) {
    var isArr = isArray_default(srcValue), isBuff = !isArr && isBuffer_default(srcValue), isTyped = !isArr && !isBuff && isTypedArray_default(srcValue);
    newValue = srcValue;
    if (isArr || isBuff || isTyped) {
      if (isArray_default(objValue)) {
        newValue = objValue;
      } else if (isArrayLikeObject_default(objValue)) {
        newValue = copyArray_default(objValue);
      } else if (isBuff) {
        isCommon = false;
        newValue = cloneBuffer_default(srcValue, true);
      } else if (isTyped) {
        isCommon = false;
        newValue = cloneTypedArray_default(srcValue, true);
      } else {
        newValue = [];
      }
    } else if (isPlainObject_default(srcValue) || isArguments_default(srcValue)) {
      newValue = objValue;
      if (isArguments_default(objValue)) {
        newValue = toPlainObject_default(objValue);
      } else if (!isObject_default(objValue) || isFunction_default(objValue)) {
        newValue = initCloneObject_default(srcValue);
      }
    } else {
      isCommon = false;
    }
  }
  if (isCommon) {
    stack.set(srcValue, newValue);
    mergeFunc(newValue, srcValue, srcIndex, customizer, stack);
    stack["delete"](srcValue);
  }
  assignMergeValue_default(object, key, newValue);
}
var baseMergeDeep_default = baseMergeDeep;

// node_modules/lodash-es/_baseMerge.js
function baseMerge(object, source, srcIndex, customizer, stack) {
  if (object === source) {
    return;
  }
  baseFor_default(source, function(srcValue, key) {
    stack || (stack = new Stack_default());
    if (isObject_default(srcValue)) {
      baseMergeDeep_default(object, source, key, srcIndex, baseMerge, customizer, stack);
    } else {
      var newValue = customizer ? customizer(safeGet_default(object, key), srcValue, key + "", object, source, stack) : void 0;
      if (newValue === void 0) {
        newValue = srcValue;
      }
      assignMergeValue_default(object, key, newValue);
    }
  }, keysIn_default);
}
var baseMerge_default = baseMerge;

// node_modules/lodash-es/_customDefaultsMerge.js
function customDefaultsMerge(objValue, srcValue, key, object, source, stack) {
  if (isObject_default(objValue) && isObject_default(srcValue)) {
    stack.set(srcValue, objValue);
    baseMerge_default(objValue, srcValue, void 0, customDefaultsMerge, stack);
    stack["delete"](srcValue);
  }
  return objValue;
}
var customDefaultsMerge_default = customDefaultsMerge;

// node_modules/lodash-es/mergeWith.js
var mergeWith = createAssigner_default(function(object, source, srcIndex, customizer) {
  baseMerge_default(object, source, srcIndex, customizer);
});
var mergeWith_default = mergeWith;

// node_modules/lodash-es/defaultsDeep.js
var defaultsDeep = baseRest_default(function(args) {
  args.push(void 0, customDefaultsMerge_default);
  return apply_default(mergeWith_default, void 0, args);
});
var defaultsDeep_default = defaultsDeep;

// node_modules/lodash-es/_baseDelay.js
var FUNC_ERROR_TEXT7 = "Expected a function";
function baseDelay(func, wait, args) {
  if (typeof func != "function") {
    throw new TypeError(FUNC_ERROR_TEXT7);
  }
  return setTimeout(function() {
    func.apply(void 0, args);
  }, wait);
}
var baseDelay_default = baseDelay;

// node_modules/lodash-es/defer.js
var defer = baseRest_default(function(func, args) {
  return baseDelay_default(func, 1, args);
});
var defer_default = defer;

// node_modules/lodash-es/delay.js
var delay = baseRest_default(function(func, wait, args) {
  return baseDelay_default(func, toNumber_default(wait) || 0, args);
});
var delay_default = delay;

// node_modules/lodash-es/_arrayIncludesWith.js
function arrayIncludesWith(array, value, comparator) {
  var index = -1, length = array == null ? 0 : array.length;
  while (++index < length) {
    if (comparator(value, array[index])) {
      return true;
    }
  }
  return false;
}
var arrayIncludesWith_default = arrayIncludesWith;

// node_modules/lodash-es/_baseDifference.js
var LARGE_ARRAY_SIZE2 = 200;
function baseDifference(array, values2, iteratee2, comparator) {
  var index = -1, includes2 = arrayIncludes_default, isCommon = true, length = array.length, result2 = [], valuesLength = values2.length;
  if (!length) {
    return result2;
  }
  if (iteratee2) {
    values2 = arrayMap_default(values2, baseUnary_default(iteratee2));
  }
  if (comparator) {
    includes2 = arrayIncludesWith_default;
    isCommon = false;
  } else if (values2.length >= LARGE_ARRAY_SIZE2) {
    includes2 = cacheHas_default;
    isCommon = false;
    values2 = new SetCache_default(values2);
  }
  outer: while (++index < length) {
    var value = array[index], computed = iteratee2 == null ? value : iteratee2(value);
    value = comparator || value !== 0 ? value : 0;
    if (isCommon && computed === computed) {
      var valuesIndex = valuesLength;
      while (valuesIndex--) {
        if (values2[valuesIndex] === computed) {
          continue outer;
        }
      }
      result2.push(value);
    } else if (!includes2(values2, computed, comparator)) {
      result2.push(value);
    }
  }
  return result2;
}
var baseDifference_default = baseDifference;

// node_modules/lodash-es/difference.js
var difference = baseRest_default(function(array, values2) {
  return isArrayLikeObject_default(array) ? baseDifference_default(array, baseFlatten_default(values2, 1, isArrayLikeObject_default, true)) : [];
});
var difference_default = difference;

// node_modules/lodash-es/last.js
function last(array) {
  var length = array == null ? 0 : array.length;
  return length ? array[length - 1] : void 0;
}
var last_default = last;

// node_modules/lodash-es/differenceBy.js
var differenceBy = baseRest_default(function(array, values2) {
  var iteratee2 = last_default(values2);
  if (isArrayLikeObject_default(iteratee2)) {
    iteratee2 = void 0;
  }
  return isArrayLikeObject_default(array) ? baseDifference_default(array, baseFlatten_default(values2, 1, isArrayLikeObject_default, true), baseIteratee_default(iteratee2, 2)) : [];
});
var differenceBy_default = differenceBy;

// node_modules/lodash-es/differenceWith.js
var differenceWith = baseRest_default(function(array, values2) {
  var comparator = last_default(values2);
  if (isArrayLikeObject_default(comparator)) {
    comparator = void 0;
  }
  return isArrayLikeObject_default(array) ? baseDifference_default(array, baseFlatten_default(values2, 1, isArrayLikeObject_default, true), void 0, comparator) : [];
});
var differenceWith_default = differenceWith;

// node_modules/lodash-es/divide.js
var divide = createMathOperation_default(function(dividend, divisor) {
  return dividend / divisor;
}, 1);
var divide_default = divide;

// node_modules/lodash-es/drop.js
function drop(array, n, guard) {
  var length = array == null ? 0 : array.length;
  if (!length) {
    return [];
  }
  n = guard || n === void 0 ? 1 : toInteger_default(n);
  return baseSlice_default(array, n < 0 ? 0 : n, length);
}
var drop_default = drop;

// node_modules/lodash-es/dropRight.js
function dropRight(array, n, guard) {
  var length = array == null ? 0 : array.length;
  if (!length) {
    return [];
  }
  n = guard || n === void 0 ? 1 : toInteger_default(n);
  n = length - n;
  return baseSlice_default(array, 0, n < 0 ? 0 : n);
}
var dropRight_default = dropRight;

// node_modules/lodash-es/_baseWhile.js
function baseWhile(array, predicate, isDrop, fromRight) {
  var length = array.length, index = fromRight ? length : -1;
  while ((fromRight ? index-- : ++index < length) && predicate(array[index], index, array)) {
  }
  return isDrop ? baseSlice_default(array, fromRight ? 0 : index, fromRight ? index + 1 : length) : baseSlice_default(array, fromRight ? index + 1 : 0, fromRight ? length : index);
}
var baseWhile_default = baseWhile;

// node_modules/lodash-es/dropRightWhile.js
function dropRightWhile(array, predicate) {
  return array && array.length ? baseWhile_default(array, baseIteratee_default(predicate, 3), true, true) : [];
}
var dropRightWhile_default = dropRightWhile;

// node_modules/lodash-es/dropWhile.js
function dropWhile(array, predicate) {
  return array && array.length ? baseWhile_default(array, baseIteratee_default(predicate, 3), true) : [];
}
var dropWhile_default = dropWhile;

// node_modules/lodash-es/_castFunction.js
function castFunction(value) {
  return typeof value == "function" ? value : identity_default;
}
var castFunction_default = castFunction;

// node_modules/lodash-es/forEach.js
function forEach(collection, iteratee2) {
  var func = isArray_default(collection) ? arrayEach_default : baseEach_default;
  return func(collection, castFunction_default(iteratee2));
}
var forEach_default = forEach;

// node_modules/lodash-es/_arrayEachRight.js
function arrayEachRight(array, iteratee2) {
  var length = array == null ? 0 : array.length;
  while (length--) {
    if (iteratee2(array[length], length, array) === false) {
      break;
    }
  }
  return array;
}
var arrayEachRight_default = arrayEachRight;

// node_modules/lodash-es/_baseForRight.js
var baseForRight = createBaseFor_default(true);
var baseForRight_default = baseForRight;

// node_modules/lodash-es/_baseForOwnRight.js
function baseForOwnRight(object, iteratee2) {
  return object && baseForRight_default(object, iteratee2, keys_default);
}
var baseForOwnRight_default = baseForOwnRight;

// node_modules/lodash-es/_baseEachRight.js
var baseEachRight = createBaseEach_default(baseForOwnRight_default, true);
var baseEachRight_default = baseEachRight;

// node_modules/lodash-es/forEachRight.js
function forEachRight(collection, iteratee2) {
  var func = isArray_default(collection) ? arrayEachRight_default : baseEachRight_default;
  return func(collection, castFunction_default(iteratee2));
}
var forEachRight_default = forEachRight;

// node_modules/lodash-es/endsWith.js
function endsWith(string, target, position) {
  string = toString_default(string);
  target = baseToString_default(target);
  var length = string.length;
  position = position === void 0 ? length : baseClamp_default(toInteger_default(position), 0, length);
  var end = position;
  position -= target.length;
  return position >= 0 && string.slice(position, end) == target;
}
var endsWith_default = endsWith;

// node_modules/lodash-es/_baseToPairs.js
function baseToPairs(object, props) {
  return arrayMap_default(props, function(key) {
    return [key, object[key]];
  });
}
var baseToPairs_default = baseToPairs;

// node_modules/lodash-es/_setToPairs.js
function setToPairs(set2) {
  var index = -1, result2 = Array(set2.size);
  set2.forEach(function(value) {
    result2[++index] = [value, value];
  });
  return result2;
}
var setToPairs_default = setToPairs;

// node_modules/lodash-es/_createToPairs.js
var mapTag7 = "[object Map]";
var setTag7 = "[object Set]";
function createToPairs(keysFunc) {
  return function(object) {
    var tag = getTag_default(object);
    if (tag == mapTag7) {
      return mapToArray_default(object);
    }
    if (tag == setTag7) {
      return setToPairs_default(object);
    }
    return baseToPairs_default(object, keysFunc(object));
  };
}
var createToPairs_default = createToPairs;

// node_modules/lodash-es/toPairs.js
var toPairs = createToPairs_default(keys_default);
var toPairs_default = toPairs;

// node_modules/lodash-es/toPairsIn.js
var toPairsIn = createToPairs_default(keysIn_default);
var toPairsIn_default = toPairsIn;

// node_modules/lodash-es/_escapeHtmlChar.js
var htmlEscapes = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;"
};
var escapeHtmlChar = basePropertyOf_default(htmlEscapes);
var escapeHtmlChar_default = escapeHtmlChar;

// node_modules/lodash-es/escape.js
var reUnescapedHtml = /[&<>"']/g;
var reHasUnescapedHtml = RegExp(reUnescapedHtml.source);
function escape(string) {
  string = toString_default(string);
  return string && reHasUnescapedHtml.test(string) ? string.replace(reUnescapedHtml, escapeHtmlChar_default) : string;
}
var escape_default = escape;

// node_modules/lodash-es/escapeRegExp.js
var reRegExpChar2 = /[\\^$.*+?()[\]{}|]/g;
var reHasRegExpChar = RegExp(reRegExpChar2.source);
function escapeRegExp(string) {
  string = toString_default(string);
  return string && reHasRegExpChar.test(string) ? string.replace(reRegExpChar2, "\\$&") : string;
}
var escapeRegExp_default = escapeRegExp;

// node_modules/lodash-es/_arrayEvery.js
function arrayEvery(array, predicate) {
  var index = -1, length = array == null ? 0 : array.length;
  while (++index < length) {
    if (!predicate(array[index], index, array)) {
      return false;
    }
  }
  return true;
}
var arrayEvery_default = arrayEvery;

// node_modules/lodash-es/_baseEvery.js
function baseEvery(collection, predicate) {
  var result2 = true;
  baseEach_default(collection, function(value, index, collection2) {
    result2 = !!predicate(value, index, collection2);
    return result2;
  });
  return result2;
}
var baseEvery_default = baseEvery;

// node_modules/lodash-es/every.js
function every(collection, predicate, guard) {
  var func = isArray_default(collection) ? arrayEvery_default : baseEvery_default;
  if (guard && isIterateeCall_default(collection, predicate, guard)) {
    predicate = void 0;
  }
  return func(collection, baseIteratee_default(predicate, 3));
}
var every_default = every;

// node_modules/lodash-es/toLength.js
var MAX_ARRAY_LENGTH2 = 4294967295;
function toLength(value) {
  return value ? baseClamp_default(toInteger_default(value), 0, MAX_ARRAY_LENGTH2) : 0;
}
var toLength_default = toLength;

// node_modules/lodash-es/_baseFill.js
function baseFill(array, value, start, end) {
  var length = array.length;
  start = toInteger_default(start);
  if (start < 0) {
    start = -start > length ? 0 : length + start;
  }
  end = end === void 0 || end > length ? length : toInteger_default(end);
  if (end < 0) {
    end += length;
  }
  end = start > end ? 0 : toLength_default(end);
  while (start < end) {
    array[start++] = value;
  }
  return array;
}
var baseFill_default = baseFill;

// node_modules/lodash-es/fill.js
function fill(array, value, start, end) {
  var length = array == null ? 0 : array.length;
  if (!length) {
    return [];
  }
  if (start && typeof start != "number" && isIterateeCall_default(array, value, start)) {
    start = 0;
    end = length;
  }
  return baseFill_default(array, value, start, end);
}
var fill_default = fill;

// node_modules/lodash-es/_baseFilter.js
function baseFilter(collection, predicate) {
  var result2 = [];
  baseEach_default(collection, function(value, index, collection2) {
    if (predicate(value, index, collection2)) {
      result2.push(value);
    }
  });
  return result2;
}
var baseFilter_default = baseFilter;

// node_modules/lodash-es/filter.js
function filter(collection, predicate) {
  var func = isArray_default(collection) ? arrayFilter_default : baseFilter_default;
  return func(collection, baseIteratee_default(predicate, 3));
}
var filter_default = filter;

// node_modules/lodash-es/_createFind.js
function createFind(findIndexFunc) {
  return function(collection, predicate, fromIndex) {
    var iterable = Object(collection);
    if (!isArrayLike_default(collection)) {
      var iteratee2 = baseIteratee_default(predicate, 3);
      collection = keys_default(collection);
      predicate = function(key) {
        return iteratee2(iterable[key], key, iterable);
      };
    }
    var index = findIndexFunc(collection, predicate, fromIndex);
    return index > -1 ? iterable[iteratee2 ? collection[index] : index] : void 0;
  };
}
var createFind_default = createFind;

// node_modules/lodash-es/findIndex.js
var nativeMax7 = Math.max;
function findIndex(array, predicate, fromIndex) {
  var length = array == null ? 0 : array.length;
  if (!length) {
    return -1;
  }
  var index = fromIndex == null ? 0 : toInteger_default(fromIndex);
  if (index < 0) {
    index = nativeMax7(length + index, 0);
  }
  return baseFindIndex_default(array, baseIteratee_default(predicate, 3), index);
}
var findIndex_default = findIndex;

// node_modules/lodash-es/find.js
var find = createFind_default(findIndex_default);
var find_default = find;

// node_modules/lodash-es/_baseFindKey.js
function baseFindKey(collection, predicate, eachFunc) {
  var result2;
  eachFunc(collection, function(value, key, collection2) {
    if (predicate(value, key, collection2)) {
      result2 = key;
      return false;
    }
  });
  return result2;
}
var baseFindKey_default = baseFindKey;

// node_modules/lodash-es/findKey.js
function findKey(object, predicate) {
  return baseFindKey_default(object, baseIteratee_default(predicate, 3), baseForOwn_default);
}
var findKey_default = findKey;

// node_modules/lodash-es/findLastIndex.js
var nativeMax8 = Math.max;
var nativeMin5 = Math.min;
function findLastIndex(array, predicate, fromIndex) {
  var length = array == null ? 0 : array.length;
  if (!length) {
    return -1;
  }
  var index = length - 1;
  if (fromIndex !== void 0) {
    index = toInteger_default(fromIndex);
    index = fromIndex < 0 ? nativeMax8(length + index, 0) : nativeMin5(index, length - 1);
  }
  return baseFindIndex_default(array, baseIteratee_default(predicate, 3), index, true);
}
var findLastIndex_default = findLastIndex;

// node_modules/lodash-es/findLast.js
var findLast = createFind_default(findLastIndex_default);
var findLast_default = findLast;

// node_modules/lodash-es/findLastKey.js
function findLastKey(object, predicate) {
  return baseFindKey_default(object, baseIteratee_default(predicate, 3), baseForOwnRight_default);
}
var findLastKey_default = findLastKey;

// node_modules/lodash-es/head.js
function head(array) {
  return array && array.length ? array[0] : void 0;
}
var head_default = head;

// node_modules/lodash-es/_baseMap.js
function baseMap(collection, iteratee2) {
  var index = -1, result2 = isArrayLike_default(collection) ? Array(collection.length) : [];
  baseEach_default(collection, function(value, key, collection2) {
    result2[++index] = iteratee2(value, key, collection2);
  });
  return result2;
}
var baseMap_default = baseMap;

// node_modules/lodash-es/map.js
function map(collection, iteratee2) {
  var func = isArray_default(collection) ? arrayMap_default : baseMap_default;
  return func(collection, baseIteratee_default(iteratee2, 3));
}
var map_default = map;

// node_modules/lodash-es/flatMap.js
function flatMap(collection, iteratee2) {
  return baseFlatten_default(map_default(collection, iteratee2), 1);
}
var flatMap_default = flatMap;

// node_modules/lodash-es/flatMapDeep.js
var INFINITY4 = 1 / 0;
function flatMapDeep(collection, iteratee2) {
  return baseFlatten_default(map_default(collection, iteratee2), INFINITY4);
}
var flatMapDeep_default = flatMapDeep;

// node_modules/lodash-es/flatMapDepth.js
function flatMapDepth(collection, iteratee2, depth) {
  depth = depth === void 0 ? 1 : toInteger_default(depth);
  return baseFlatten_default(map_default(collection, iteratee2), depth);
}
var flatMapDepth_default = flatMapDepth;

// node_modules/lodash-es/flattenDeep.js
var INFINITY5 = 1 / 0;
function flattenDeep(array) {
  var length = array == null ? 0 : array.length;
  return length ? baseFlatten_default(array, INFINITY5) : [];
}
var flattenDeep_default = flattenDeep;

// node_modules/lodash-es/flattenDepth.js
function flattenDepth(array, depth) {
  var length = array == null ? 0 : array.length;
  if (!length) {
    return [];
  }
  depth = depth === void 0 ? 1 : toInteger_default(depth);
  return baseFlatten_default(array, depth);
}
var flattenDepth_default = flattenDepth;

// node_modules/lodash-es/flip.js
var WRAP_FLIP_FLAG3 = 512;
function flip(func) {
  return createWrap_default(func, WRAP_FLIP_FLAG3);
}
var flip_default = flip;

// node_modules/lodash-es/floor.js
var floor = createRound_default("floor");
var floor_default = floor;

// node_modules/lodash-es/_createFlow.js
var FUNC_ERROR_TEXT8 = "Expected a function";
var WRAP_CURRY_FLAG7 = 8;
var WRAP_PARTIAL_FLAG6 = 32;
var WRAP_ARY_FLAG5 = 128;
var WRAP_REARG_FLAG3 = 256;
function createFlow(fromRight) {
  return flatRest_default(function(funcs) {
    var length = funcs.length, index = length, prereq = LodashWrapper_default.prototype.thru;
    if (fromRight) {
      funcs.reverse();
    }
    while (index--) {
      var func = funcs[index];
      if (typeof func != "function") {
        throw new TypeError(FUNC_ERROR_TEXT8);
      }
      if (prereq && !wrapper && getFuncName_default(func) == "wrapper") {
        var wrapper = new LodashWrapper_default([], true);
      }
    }
    index = wrapper ? index : length;
    while (++index < length) {
      func = funcs[index];
      var funcName = getFuncName_default(func), data = funcName == "wrapper" ? getData_default(func) : void 0;
      if (data && isLaziable_default(data[0]) && data[1] == (WRAP_ARY_FLAG5 | WRAP_CURRY_FLAG7 | WRAP_PARTIAL_FLAG6 | WRAP_REARG_FLAG3) && !data[4].length && data[9] == 1) {
        wrapper = wrapper[getFuncName_default(data[0])].apply(wrapper, data[3]);
      } else {
        wrapper = func.length == 1 && isLaziable_default(func) ? wrapper[funcName]() : wrapper.thru(func);
      }
    }
    return function() {
      var args = arguments, value = args[0];
      if (wrapper && args.length == 1 && isArray_default(value)) {
        return wrapper.plant(value).value();
      }
      var index2 = 0, result2 = length ? funcs[index2].apply(this, args) : value;
      while (++index2 < length) {
        result2 = funcs[index2].call(this, result2);
      }
      return result2;
    };
  });
}
var createFlow_default = createFlow;

// node_modules/lodash-es/flow.js
var flow = createFlow_default();
var flow_default = flow;

// node_modules/lodash-es/flowRight.js
var flowRight = createFlow_default(true);
var flowRight_default = flowRight;

// node_modules/lodash-es/forIn.js
function forIn(object, iteratee2) {
  return object == null ? object : baseFor_default(object, castFunction_default(iteratee2), keysIn_default);
}
var forIn_default = forIn;

// node_modules/lodash-es/forInRight.js
function forInRight(object, iteratee2) {
  return object == null ? object : baseForRight_default(object, castFunction_default(iteratee2), keysIn_default);
}
var forInRight_default = forInRight;

// node_modules/lodash-es/forOwn.js
function forOwn(object, iteratee2) {
  return object && baseForOwn_default(object, castFunction_default(iteratee2));
}
var forOwn_default = forOwn;

// node_modules/lodash-es/forOwnRight.js
function forOwnRight(object, iteratee2) {
  return object && baseForOwnRight_default(object, castFunction_default(iteratee2));
}
var forOwnRight_default = forOwnRight;

// node_modules/lodash-es/fromPairs.js
function fromPairs(pairs) {
  var index = -1, length = pairs == null ? 0 : pairs.length, result2 = {};
  while (++index < length) {
    var pair = pairs[index];
    result2[pair[0]] = pair[1];
  }
  return result2;
}
var fromPairs_default = fromPairs;

// node_modules/lodash-es/_baseFunctions.js
function baseFunctions(object, props) {
  return arrayFilter_default(props, function(key) {
    return isFunction_default(object[key]);
  });
}
var baseFunctions_default = baseFunctions;

// node_modules/lodash-es/functions.js
function functions(object) {
  return object == null ? [] : baseFunctions_default(object, keys_default(object));
}
var functions_default = functions;

// node_modules/lodash-es/functionsIn.js
function functionsIn(object) {
  return object == null ? [] : baseFunctions_default(object, keysIn_default(object));
}
var functionsIn_default = functionsIn;

// node_modules/lodash-es/groupBy.js
var objectProto22 = Object.prototype;
var hasOwnProperty19 = objectProto22.hasOwnProperty;
var groupBy = createAggregator_default(function(result2, value, key) {
  if (hasOwnProperty19.call(result2, key)) {
    result2[key].push(value);
  } else {
    baseAssignValue_default(result2, key, [value]);
  }
});
var groupBy_default = groupBy;

// node_modules/lodash-es/_baseGt.js
function baseGt(value, other) {
  return value > other;
}
var baseGt_default = baseGt;

// node_modules/lodash-es/_createRelationalOperation.js
function createRelationalOperation(operator) {
  return function(value, other) {
    if (!(typeof value == "string" && typeof other == "string")) {
      value = toNumber_default(value);
      other = toNumber_default(other);
    }
    return operator(value, other);
  };
}
var createRelationalOperation_default = createRelationalOperation;

// node_modules/lodash-es/gt.js
var gt = createRelationalOperation_default(baseGt_default);
var gt_default = gt;

// node_modules/lodash-es/gte.js
var gte = createRelationalOperation_default(function(value, other) {
  return value >= other;
});
var gte_default = gte;

// node_modules/lodash-es/_baseHas.js
var objectProto23 = Object.prototype;
var hasOwnProperty20 = objectProto23.hasOwnProperty;
function baseHas(object, key) {
  return object != null && hasOwnProperty20.call(object, key);
}
var baseHas_default = baseHas;

// node_modules/lodash-es/has.js
function has(object, path) {
  return object != null && hasPath_default(object, path, baseHas_default);
}
var has_default = has;

// node_modules/lodash-es/_baseInRange.js
var nativeMax9 = Math.max;
var nativeMin6 = Math.min;
function baseInRange(number, start, end) {
  return number >= nativeMin6(start, end) && number < nativeMax9(start, end);
}
var baseInRange_default = baseInRange;

// node_modules/lodash-es/inRange.js
function inRange(number, start, end) {
  start = toFinite_default(start);
  if (end === void 0) {
    end = start;
    start = 0;
  } else {
    end = toFinite_default(end);
  }
  number = toNumber_default(number);
  return baseInRange_default(number, start, end);
}
var inRange_default = inRange;

// node_modules/lodash-es/isString.js
var stringTag5 = "[object String]";
function isString(value) {
  return typeof value == "string" || !isArray_default(value) && isObjectLike_default(value) && baseGetTag_default(value) == stringTag5;
}
var isString_default = isString;

// node_modules/lodash-es/_baseValues.js
function baseValues(object, props) {
  return arrayMap_default(props, function(key) {
    return object[key];
  });
}
var baseValues_default = baseValues;

// node_modules/lodash-es/values.js
function values(object) {
  return object == null ? [] : baseValues_default(object, keys_default(object));
}
var values_default = values;

// node_modules/lodash-es/includes.js
var nativeMax10 = Math.max;
function includes(collection, value, fromIndex, guard) {
  collection = isArrayLike_default(collection) ? collection : values_default(collection);
  fromIndex = fromIndex && !guard ? toInteger_default(fromIndex) : 0;
  var length = collection.length;
  if (fromIndex < 0) {
    fromIndex = nativeMax10(length + fromIndex, 0);
  }
  return isString_default(collection) ? fromIndex <= length && collection.indexOf(value, fromIndex) > -1 : !!length && baseIndexOf_default(collection, value, fromIndex) > -1;
}
var includes_default = includes;

// node_modules/lodash-es/indexOf.js
var nativeMax11 = Math.max;
function indexOf(array, value, fromIndex) {
  var length = array == null ? 0 : array.length;
  if (!length) {
    return -1;
  }
  var index = fromIndex == null ? 0 : toInteger_default(fromIndex);
  if (index < 0) {
    index = nativeMax11(length + index, 0);
  }
  return baseIndexOf_default(array, value, index);
}
var indexOf_default = indexOf;

// node_modules/lodash-es/initial.js
function initial(array) {
  var length = array == null ? 0 : array.length;
  return length ? baseSlice_default(array, 0, -1) : [];
}
var initial_default = initial;

// node_modules/lodash-es/_baseIntersection.js
var nativeMin7 = Math.min;
function baseIntersection(arrays, iteratee2, comparator) {
  var includes2 = comparator ? arrayIncludesWith_default : arrayIncludes_default, length = arrays[0].length, othLength = arrays.length, othIndex = othLength, caches = Array(othLength), maxLength = Infinity, result2 = [];
  while (othIndex--) {
    var array = arrays[othIndex];
    if (othIndex && iteratee2) {
      array = arrayMap_default(array, baseUnary_default(iteratee2));
    }
    maxLength = nativeMin7(array.length, maxLength);
    caches[othIndex] = !comparator && (iteratee2 || length >= 120 && array.length >= 120) ? new SetCache_default(othIndex && array) : void 0;
  }
  array = arrays[0];
  var index = -1, seen = caches[0];
  outer: while (++index < length && result2.length < maxLength) {
    var value = array[index], computed = iteratee2 ? iteratee2(value) : value;
    value = comparator || value !== 0 ? value : 0;
    if (!(seen ? cacheHas_default(seen, computed) : includes2(result2, computed, comparator))) {
      othIndex = othLength;
      while (--othIndex) {
        var cache = caches[othIndex];
        if (!(cache ? cacheHas_default(cache, computed) : includes2(arrays[othIndex], computed, comparator))) {
          continue outer;
        }
      }
      if (seen) {
        seen.push(computed);
      }
      result2.push(value);
    }
  }
  return result2;
}
var baseIntersection_default = baseIntersection;

// node_modules/lodash-es/_castArrayLikeObject.js
function castArrayLikeObject(value) {
  return isArrayLikeObject_default(value) ? value : [];
}
var castArrayLikeObject_default = castArrayLikeObject;

// node_modules/lodash-es/intersection.js
var intersection = baseRest_default(function(arrays) {
  var mapped = arrayMap_default(arrays, castArrayLikeObject_default);
  return mapped.length && mapped[0] === arrays[0] ? baseIntersection_default(mapped) : [];
});
var intersection_default = intersection;

// node_modules/lodash-es/intersectionBy.js
var intersectionBy = baseRest_default(function(arrays) {
  var iteratee2 = last_default(arrays), mapped = arrayMap_default(arrays, castArrayLikeObject_default);
  if (iteratee2 === last_default(mapped)) {
    iteratee2 = void 0;
  } else {
    mapped.pop();
  }
  return mapped.length && mapped[0] === arrays[0] ? baseIntersection_default(mapped, baseIteratee_default(iteratee2, 2)) : [];
});
var intersectionBy_default = intersectionBy;

// node_modules/lodash-es/intersectionWith.js
var intersectionWith = baseRest_default(function(arrays) {
  var comparator = last_default(arrays), mapped = arrayMap_default(arrays, castArrayLikeObject_default);
  comparator = typeof comparator == "function" ? comparator : void 0;
  if (comparator) {
    mapped.pop();
  }
  return mapped.length && mapped[0] === arrays[0] ? baseIntersection_default(mapped, void 0, comparator) : [];
});
var intersectionWith_default = intersectionWith;

// node_modules/lodash-es/_baseInverter.js
function baseInverter(object, setter, iteratee2, accumulator) {
  baseForOwn_default(object, function(value, key, object2) {
    setter(accumulator, iteratee2(value), key, object2);
  });
  return accumulator;
}
var baseInverter_default = baseInverter;

// node_modules/lodash-es/_createInverter.js
function createInverter(setter, toIteratee) {
  return function(object, iteratee2) {
    return baseInverter_default(object, setter, toIteratee(iteratee2), {});
  };
}
var createInverter_default = createInverter;

// node_modules/lodash-es/invert.js
var objectProto24 = Object.prototype;
var nativeObjectToString3 = objectProto24.toString;
var invert = createInverter_default(function(result2, value, key) {
  if (value != null && typeof value.toString != "function") {
    value = nativeObjectToString3.call(value);
  }
  result2[value] = key;
}, constant_default(identity_default));
var invert_default = invert;

// node_modules/lodash-es/invertBy.js
var objectProto25 = Object.prototype;
var hasOwnProperty21 = objectProto25.hasOwnProperty;
var nativeObjectToString4 = objectProto25.toString;
var invertBy = createInverter_default(function(result2, value, key) {
  if (value != null && typeof value.toString != "function") {
    value = nativeObjectToString4.call(value);
  }
  if (hasOwnProperty21.call(result2, value)) {
    result2[value].push(key);
  } else {
    result2[value] = [key];
  }
}, baseIteratee_default);
var invertBy_default = invertBy;

// node_modules/lodash-es/_parent.js
function parent(object, path) {
  return path.length < 2 ? object : baseGet_default(object, baseSlice_default(path, 0, -1));
}
var parent_default = parent;

// node_modules/lodash-es/_baseInvoke.js
function baseInvoke(object, path, args) {
  path = castPath_default(path, object);
  object = parent_default(object, path);
  var func = object == null ? object : object[toKey_default(last_default(path))];
  return func == null ? void 0 : apply_default(func, object, args);
}
var baseInvoke_default = baseInvoke;

// node_modules/lodash-es/invoke.js
var invoke = baseRest_default(baseInvoke_default);
var invoke_default = invoke;

// node_modules/lodash-es/invokeMap.js
var invokeMap = baseRest_default(function(collection, path, args) {
  var index = -1, isFunc = typeof path == "function", result2 = isArrayLike_default(collection) ? Array(collection.length) : [];
  baseEach_default(collection, function(value) {
    result2[++index] = isFunc ? apply_default(path, value, args) : baseInvoke_default(value, path, args);
  });
  return result2;
});
var invokeMap_default = invokeMap;

// node_modules/lodash-es/_baseIsArrayBuffer.js
var arrayBufferTag5 = "[object ArrayBuffer]";
function baseIsArrayBuffer(value) {
  return isObjectLike_default(value) && baseGetTag_default(value) == arrayBufferTag5;
}
var baseIsArrayBuffer_default = baseIsArrayBuffer;

// node_modules/lodash-es/isArrayBuffer.js
var nodeIsArrayBuffer = nodeUtil_default && nodeUtil_default.isArrayBuffer;
var isArrayBuffer = nodeIsArrayBuffer ? baseUnary_default(nodeIsArrayBuffer) : baseIsArrayBuffer_default;
var isArrayBuffer_default = isArrayBuffer;

// node_modules/lodash-es/isBoolean.js
var boolTag5 = "[object Boolean]";
function isBoolean(value) {
  return value === true || value === false || isObjectLike_default(value) && baseGetTag_default(value) == boolTag5;
}
var isBoolean_default = isBoolean;

// node_modules/lodash-es/_baseIsDate.js
var dateTag5 = "[object Date]";
function baseIsDate(value) {
  return isObjectLike_default(value) && baseGetTag_default(value) == dateTag5;
}
var baseIsDate_default = baseIsDate;

// node_modules/lodash-es/isDate.js
var nodeIsDate = nodeUtil_default && nodeUtil_default.isDate;
var isDate = nodeIsDate ? baseUnary_default(nodeIsDate) : baseIsDate_default;
var isDate_default = isDate;

// node_modules/lodash-es/isElement.js
function isElement(value) {
  return isObjectLike_default(value) && value.nodeType === 1 && !isPlainObject_default(value);
}
var isElement_default = isElement;

// node_modules/lodash-es/isEmpty.js
var mapTag8 = "[object Map]";
var setTag8 = "[object Set]";
var objectProto26 = Object.prototype;
var hasOwnProperty22 = objectProto26.hasOwnProperty;
function isEmpty(value) {
  if (value == null) {
    return true;
  }
  if (isArrayLike_default(value) && (isArray_default(value) || typeof value == "string" || typeof value.splice == "function" || isBuffer_default(value) || isTypedArray_default(value) || isArguments_default(value))) {
    return !value.length;
  }
  var tag = getTag_default(value);
  if (tag == mapTag8 || tag == setTag8) {
    return !value.size;
  }
  if (isPrototype_default(value)) {
    return !baseKeys_default(value).length;
  }
  for (var key in value) {
    if (hasOwnProperty22.call(value, key)) {
      return false;
    }
  }
  return true;
}
var isEmpty_default = isEmpty;

// node_modules/lodash-es/isEqual.js
function isEqual(value, other) {
  return baseIsEqual_default(value, other);
}
var isEqual_default = isEqual;

// node_modules/lodash-es/isEqualWith.js
function isEqualWith(value, other, customizer) {
  customizer = typeof customizer == "function" ? customizer : void 0;
  var result2 = customizer ? customizer(value, other) : void 0;
  return result2 === void 0 ? baseIsEqual_default(value, other, void 0, customizer) : !!result2;
}
var isEqualWith_default = isEqualWith;

// node_modules/lodash-es/isFinite.js
var nativeIsFinite2 = root_default.isFinite;
function isFinite(value) {
  return typeof value == "number" && nativeIsFinite2(value);
}
var isFinite_default = isFinite;

// node_modules/lodash-es/isInteger.js
function isInteger(value) {
  return typeof value == "number" && value == toInteger_default(value);
}
var isInteger_default = isInteger;

// node_modules/lodash-es/isMatch.js
function isMatch(object, source) {
  return object === source || baseIsMatch_default(object, source, getMatchData_default(source));
}
var isMatch_default = isMatch;

// node_modules/lodash-es/isMatchWith.js
function isMatchWith(object, source, customizer) {
  customizer = typeof customizer == "function" ? customizer : void 0;
  return baseIsMatch_default(object, source, getMatchData_default(source), customizer);
}
var isMatchWith_default = isMatchWith;

// node_modules/lodash-es/isNumber.js
var numberTag5 = "[object Number]";
function isNumber(value) {
  return typeof value == "number" || isObjectLike_default(value) && baseGetTag_default(value) == numberTag5;
}
var isNumber_default = isNumber;

// node_modules/lodash-es/isNaN.js
function isNaN(value) {
  return isNumber_default(value) && value != +value;
}
var isNaN_default = isNaN;

// node_modules/lodash-es/_isMaskable.js
var isMaskable = coreJsData_default ? isFunction_default : stubFalse_default;
var isMaskable_default = isMaskable;

// node_modules/lodash-es/isNative.js
var CORE_ERROR_TEXT = "Unsupported core-js use. Try https://npms.io/search?q=ponyfill.";
function isNative(value) {
  if (isMaskable_default(value)) {
    throw new Error(CORE_ERROR_TEXT);
  }
  return baseIsNative_default(value);
}
var isNative_default = isNative;

// node_modules/lodash-es/isNil.js
function isNil(value) {
  return value == null;
}
var isNil_default = isNil;

// node_modules/lodash-es/isNull.js
function isNull(value) {
  return value === null;
}
var isNull_default = isNull;

// node_modules/lodash-es/_baseIsRegExp.js
var regexpTag5 = "[object RegExp]";
function baseIsRegExp(value) {
  return isObjectLike_default(value) && baseGetTag_default(value) == regexpTag5;
}
var baseIsRegExp_default = baseIsRegExp;

// node_modules/lodash-es/isRegExp.js
var nodeIsRegExp = nodeUtil_default && nodeUtil_default.isRegExp;
var isRegExp = nodeIsRegExp ? baseUnary_default(nodeIsRegExp) : baseIsRegExp_default;
var isRegExp_default = isRegExp;

// node_modules/lodash-es/isSafeInteger.js
var MAX_SAFE_INTEGER3 = 9007199254740991;
function isSafeInteger(value) {
  return isInteger_default(value) && value >= -MAX_SAFE_INTEGER3 && value <= MAX_SAFE_INTEGER3;
}
var isSafeInteger_default = isSafeInteger;

// node_modules/lodash-es/isUndefined.js
function isUndefined(value) {
  return value === void 0;
}
var isUndefined_default = isUndefined;

// node_modules/lodash-es/isWeakMap.js
var weakMapTag4 = "[object WeakMap]";
function isWeakMap(value) {
  return isObjectLike_default(value) && getTag_default(value) == weakMapTag4;
}
var isWeakMap_default = isWeakMap;

// node_modules/lodash-es/isWeakSet.js
var weakSetTag = "[object WeakSet]";
function isWeakSet(value) {
  return isObjectLike_default(value) && baseGetTag_default(value) == weakSetTag;
}
var isWeakSet_default = isWeakSet;

// node_modules/lodash-es/iteratee.js
var CLONE_DEEP_FLAG5 = 1;
function iteratee(func) {
  return baseIteratee_default(typeof func == "function" ? func : baseClone_default(func, CLONE_DEEP_FLAG5));
}
var iteratee_default = iteratee;

// node_modules/lodash-es/join.js
var arrayProto2 = Array.prototype;
var nativeJoin = arrayProto2.join;
function join(array, separator) {
  return array == null ? "" : nativeJoin.call(array, separator);
}
var join_default = join;

// node_modules/lodash-es/kebabCase.js
var kebabCase = createCompounder_default(function(result2, word, index) {
  return result2 + (index ? "-" : "") + word.toLowerCase();
});
var kebabCase_default = kebabCase;

// node_modules/lodash-es/keyBy.js
var keyBy = createAggregator_default(function(result2, value, key) {
  baseAssignValue_default(result2, key, value);
});
var keyBy_default = keyBy;

// node_modules/lodash-es/_strictLastIndexOf.js
function strictLastIndexOf(array, value, fromIndex) {
  var index = fromIndex + 1;
  while (index--) {
    if (array[index] === value) {
      return index;
    }
  }
  return index;
}
var strictLastIndexOf_default = strictLastIndexOf;

// node_modules/lodash-es/lastIndexOf.js
var nativeMax12 = Math.max;
var nativeMin8 = Math.min;
function lastIndexOf(array, value, fromIndex) {
  var length = array == null ? 0 : array.length;
  if (!length) {
    return -1;
  }
  var index = length;
  if (fromIndex !== void 0) {
    index = toInteger_default(fromIndex);
    index = index < 0 ? nativeMax12(length + index, 0) : nativeMin8(index, length - 1);
  }
  return value === value ? strictLastIndexOf_default(array, value, index) : baseFindIndex_default(array, baseIsNaN_default, index, true);
}
var lastIndexOf_default = lastIndexOf;

// node_modules/lodash-es/lowerCase.js
var lowerCase = createCompounder_default(function(result2, word, index) {
  return result2 + (index ? " " : "") + word.toLowerCase();
});
var lowerCase_default = lowerCase;

// node_modules/lodash-es/lowerFirst.js
var lowerFirst = createCaseFirst_default("toLowerCase");
var lowerFirst_default = lowerFirst;

// node_modules/lodash-es/_baseLt.js
function baseLt(value, other) {
  return value < other;
}
var baseLt_default = baseLt;

// node_modules/lodash-es/lt.js
var lt = createRelationalOperation_default(baseLt_default);
var lt_default = lt;

// node_modules/lodash-es/lte.js
var lte = createRelationalOperation_default(function(value, other) {
  return value <= other;
});
var lte_default = lte;

// node_modules/lodash-es/mapKeys.js
function mapKeys(object, iteratee2) {
  var result2 = {};
  iteratee2 = baseIteratee_default(iteratee2, 3);
  baseForOwn_default(object, function(value, key, object2) {
    baseAssignValue_default(result2, iteratee2(value, key, object2), value);
  });
  return result2;
}
var mapKeys_default = mapKeys;

// node_modules/lodash-es/mapValues.js
function mapValues(object, iteratee2) {
  var result2 = {};
  iteratee2 = baseIteratee_default(iteratee2, 3);
  baseForOwn_default(object, function(value, key, object2) {
    baseAssignValue_default(result2, key, iteratee2(value, key, object2));
  });
  return result2;
}
var mapValues_default = mapValues;

// node_modules/lodash-es/matches.js
var CLONE_DEEP_FLAG6 = 1;
function matches(source) {
  return baseMatches_default(baseClone_default(source, CLONE_DEEP_FLAG6));
}
var matches_default = matches;

// node_modules/lodash-es/matchesProperty.js
var CLONE_DEEP_FLAG7 = 1;
function matchesProperty(path, srcValue) {
  return baseMatchesProperty_default(path, baseClone_default(srcValue, CLONE_DEEP_FLAG7));
}
var matchesProperty_default = matchesProperty;

// node_modules/lodash-es/_baseExtremum.js
function baseExtremum(array, iteratee2, comparator) {
  var index = -1, length = array.length;
  while (++index < length) {
    var value = array[index], current = iteratee2(value);
    if (current != null && (computed === void 0 ? current === current && !isSymbol_default(current) : comparator(current, computed))) {
      var computed = current, result2 = value;
    }
  }
  return result2;
}
var baseExtremum_default = baseExtremum;

// node_modules/lodash-es/max.js
function max(array) {
  return array && array.length ? baseExtremum_default(array, identity_default, baseGt_default) : void 0;
}
var max_default = max;

// node_modules/lodash-es/maxBy.js
function maxBy(array, iteratee2) {
  return array && array.length ? baseExtremum_default(array, baseIteratee_default(iteratee2, 2), baseGt_default) : void 0;
}
var maxBy_default = maxBy;

// node_modules/lodash-es/_baseSum.js
function baseSum(array, iteratee2) {
  var result2, index = -1, length = array.length;
  while (++index < length) {
    var current = iteratee2(array[index]);
    if (current !== void 0) {
      result2 = result2 === void 0 ? current : result2 + current;
    }
  }
  return result2;
}
var baseSum_default = baseSum;

// node_modules/lodash-es/_baseMean.js
var NAN3 = 0 / 0;
function baseMean(array, iteratee2) {
  var length = array == null ? 0 : array.length;
  return length ? baseSum_default(array, iteratee2) / length : NAN3;
}
var baseMean_default = baseMean;

// node_modules/lodash-es/mean.js
function mean(array) {
  return baseMean_default(array, identity_default);
}
var mean_default = mean;

// node_modules/lodash-es/meanBy.js
function meanBy(array, iteratee2) {
  return baseMean_default(array, baseIteratee_default(iteratee2, 2));
}
var meanBy_default = meanBy;

// node_modules/lodash-es/merge.js
var merge = createAssigner_default(function(object, source, srcIndex) {
  baseMerge_default(object, source, srcIndex);
});
var merge_default = merge;

// node_modules/lodash-es/method.js
var method = baseRest_default(function(path, args) {
  return function(object) {
    return baseInvoke_default(object, path, args);
  };
});
var method_default = method;

// node_modules/lodash-es/methodOf.js
var methodOf = baseRest_default(function(object, args) {
  return function(path) {
    return baseInvoke_default(object, path, args);
  };
});
var methodOf_default = methodOf;

// node_modules/lodash-es/min.js
function min(array) {
  return array && array.length ? baseExtremum_default(array, identity_default, baseLt_default) : void 0;
}
var min_default = min;

// node_modules/lodash-es/minBy.js
function minBy(array, iteratee2) {
  return array && array.length ? baseExtremum_default(array, baseIteratee_default(iteratee2, 2), baseLt_default) : void 0;
}
var minBy_default = minBy;

// node_modules/lodash-es/mixin.js
function mixin(object, source, options) {
  var props = keys_default(source), methodNames = baseFunctions_default(source, props);
  var chain2 = !(isObject_default(options) && "chain" in options) || !!options.chain, isFunc = isFunction_default(object);
  arrayEach_default(methodNames, function(methodName) {
    var func = source[methodName];
    object[methodName] = func;
    if (isFunc) {
      object.prototype[methodName] = function() {
        var chainAll = this.__chain__;
        if (chain2 || chainAll) {
          var result2 = object(this.__wrapped__), actions = result2.__actions__ = copyArray_default(this.__actions__);
          actions.push({
            "func": func,
            "args": arguments,
            "thisArg": object
          });
          result2.__chain__ = chainAll;
          return result2;
        }
        return func.apply(object, arrayPush_default([this.value()], arguments));
      };
    }
  });
  return object;
}
var mixin_default = mixin;

// node_modules/lodash-es/multiply.js
var multiply = createMathOperation_default(function(multiplier, multiplicand) {
  return multiplier * multiplicand;
}, 1);
var multiply_default = multiply;

// node_modules/lodash-es/negate.js
var FUNC_ERROR_TEXT9 = "Expected a function";
function negate(predicate) {
  if (typeof predicate != "function") {
    throw new TypeError(FUNC_ERROR_TEXT9);
  }
  return function() {
    var args = arguments;
    switch (args.length) {
      case 0:
        return !predicate.call(this);
      case 1:
        return !predicate.call(this, args[0]);
      case 2:
        return !predicate.call(this, args[0], args[1]);
      case 3:
        return !predicate.call(this, args[0], args[1], args[2]);
    }
    return !predicate.apply(this, args);
  };
}
var negate_default = negate;

// node_modules/lodash-es/_iteratorToArray.js
function iteratorToArray(iterator) {
  var data, result2 = [];
  while (!(data = iterator.next()).done) {
    result2.push(data.value);
  }
  return result2;
}
var iteratorToArray_default = iteratorToArray;

// node_modules/lodash-es/toArray.js
var mapTag9 = "[object Map]";
var setTag9 = "[object Set]";
var symIterator = Symbol_default ? Symbol_default.iterator : void 0;
function toArray(value) {
  if (!value) {
    return [];
  }
  if (isArrayLike_default(value)) {
    return isString_default(value) ? stringToArray_default(value) : copyArray_default(value);
  }
  if (symIterator && value[symIterator]) {
    return iteratorToArray_default(value[symIterator]());
  }
  var tag = getTag_default(value), func = tag == mapTag9 ? mapToArray_default : tag == setTag9 ? setToArray_default : values_default;
  return func(value);
}
var toArray_default = toArray;

// node_modules/lodash-es/next.js
function wrapperNext() {
  if (this.__values__ === void 0) {
    this.__values__ = toArray_default(this.value());
  }
  var done = this.__index__ >= this.__values__.length, value = done ? void 0 : this.__values__[this.__index__++];
  return {
    "done": done,
    "value": value
  };
}
var next_default = wrapperNext;

// node_modules/lodash-es/_baseNth.js
function baseNth(array, n) {
  var length = array.length;
  if (!length) {
    return;
  }
  n += n < 0 ? length : 0;
  return isIndex_default(n, length) ? array[n] : void 0;
}
var baseNth_default = baseNth;

// node_modules/lodash-es/nth.js
function nth(array, n) {
  return array && array.length ? baseNth_default(array, toInteger_default(n)) : void 0;
}
var nth_default = nth;

// node_modules/lodash-es/nthArg.js
function nthArg(n) {
  n = toInteger_default(n);
  return baseRest_default(function(args) {
    return baseNth_default(args, n);
  });
}
var nthArg_default = nthArg;

// node_modules/lodash-es/_baseUnset.js
function baseUnset(object, path) {
  path = castPath_default(path, object);
  object = parent_default(object, path);
  return object == null || delete object[toKey_default(last_default(path))];
}
var baseUnset_default = baseUnset;

// node_modules/lodash-es/_customOmitClone.js
function customOmitClone(value) {
  return isPlainObject_default(value) ? void 0 : value;
}
var customOmitClone_default = customOmitClone;

// node_modules/lodash-es/omit.js
var CLONE_DEEP_FLAG8 = 1;
var CLONE_FLAT_FLAG2 = 2;
var CLONE_SYMBOLS_FLAG6 = 4;
var omit = flatRest_default(function(object, paths) {
  var result2 = {};
  if (object == null) {
    return result2;
  }
  var isDeep = false;
  paths = arrayMap_default(paths, function(path) {
    path = castPath_default(path, object);
    isDeep || (isDeep = path.length > 1);
    return path;
  });
  copyObject_default(object, getAllKeysIn_default(object), result2);
  if (isDeep) {
    result2 = baseClone_default(result2, CLONE_DEEP_FLAG8 | CLONE_FLAT_FLAG2 | CLONE_SYMBOLS_FLAG6, customOmitClone_default);
  }
  var length = paths.length;
  while (length--) {
    baseUnset_default(result2, paths[length]);
  }
  return result2;
});
var omit_default = omit;

// node_modules/lodash-es/_baseSet.js
function baseSet(object, path, value, customizer) {
  if (!isObject_default(object)) {
    return object;
  }
  path = castPath_default(path, object);
  var index = -1, length = path.length, lastIndex = length - 1, nested = object;
  while (nested != null && ++index < length) {
    var key = toKey_default(path[index]), newValue = value;
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      return object;
    }
    if (index != lastIndex) {
      var objValue = nested[key];
      newValue = customizer ? customizer(objValue, key, nested) : void 0;
      if (newValue === void 0) {
        newValue = isObject_default(objValue) ? objValue : isIndex_default(path[index + 1]) ? [] : {};
      }
    }
    assignValue_default(nested, key, newValue);
    nested = nested[key];
  }
  return object;
}
var baseSet_default = baseSet;

// node_modules/lodash-es/_basePickBy.js
function basePickBy(object, paths, predicate) {
  var index = -1, length = paths.length, result2 = {};
  while (++index < length) {
    var path = paths[index], value = baseGet_default(object, path);
    if (predicate(value, path)) {
      baseSet_default(result2, castPath_default(path, object), value);
    }
  }
  return result2;
}
var basePickBy_default = basePickBy;

// node_modules/lodash-es/pickBy.js
function pickBy(object, predicate) {
  if (object == null) {
    return {};
  }
  var props = arrayMap_default(getAllKeysIn_default(object), function(prop) {
    return [prop];
  });
  predicate = baseIteratee_default(predicate);
  return basePickBy_default(object, props, function(value, path) {
    return predicate(value, path[0]);
  });
}
var pickBy_default = pickBy;

// node_modules/lodash-es/omitBy.js
function omitBy(object, predicate) {
  return pickBy_default(object, negate_default(baseIteratee_default(predicate)));
}
var omitBy_default = omitBy;

// node_modules/lodash-es/once.js
function once(func) {
  return before_default(2, func);
}
var once_default = once;

// node_modules/lodash-es/_baseSortBy.js
function baseSortBy(array, comparer) {
  var length = array.length;
  array.sort(comparer);
  while (length--) {
    array[length] = array[length].value;
  }
  return array;
}
var baseSortBy_default = baseSortBy;

// node_modules/lodash-es/_compareAscending.js
function compareAscending(value, other) {
  if (value !== other) {
    var valIsDefined = value !== void 0, valIsNull = value === null, valIsReflexive = value === value, valIsSymbol = isSymbol_default(value);
    var othIsDefined = other !== void 0, othIsNull = other === null, othIsReflexive = other === other, othIsSymbol = isSymbol_default(other);
    if (!othIsNull && !othIsSymbol && !valIsSymbol && value > other || valIsSymbol && othIsDefined && othIsReflexive && !othIsNull && !othIsSymbol || valIsNull && othIsDefined && othIsReflexive || !valIsDefined && othIsReflexive || !valIsReflexive) {
      return 1;
    }
    if (!valIsNull && !valIsSymbol && !othIsSymbol && value < other || othIsSymbol && valIsDefined && valIsReflexive && !valIsNull && !valIsSymbol || othIsNull && valIsDefined && valIsReflexive || !othIsDefined && valIsReflexive || !othIsReflexive) {
      return -1;
    }
  }
  return 0;
}
var compareAscending_default = compareAscending;

// node_modules/lodash-es/_compareMultiple.js
function compareMultiple(object, other, orders) {
  var index = -1, objCriteria = object.criteria, othCriteria = other.criteria, length = objCriteria.length, ordersLength = orders.length;
  while (++index < length) {
    var result2 = compareAscending_default(objCriteria[index], othCriteria[index]);
    if (result2) {
      if (index >= ordersLength) {
        return result2;
      }
      var order = orders[index];
      return result2 * (order == "desc" ? -1 : 1);
    }
  }
  return object.index - other.index;
}
var compareMultiple_default = compareMultiple;

// node_modules/lodash-es/_baseOrderBy.js
function baseOrderBy(collection, iteratees, orders) {
  if (iteratees.length) {
    iteratees = arrayMap_default(iteratees, function(iteratee2) {
      if (isArray_default(iteratee2)) {
        return function(value) {
          return baseGet_default(value, iteratee2.length === 1 ? iteratee2[0] : iteratee2);
        };
      }
      return iteratee2;
    });
  } else {
    iteratees = [identity_default];
  }
  var index = -1;
  iteratees = arrayMap_default(iteratees, baseUnary_default(baseIteratee_default));
  var result2 = baseMap_default(collection, function(value, key, collection2) {
    var criteria = arrayMap_default(iteratees, function(iteratee2) {
      return iteratee2(value);
    });
    return {
      "criteria": criteria,
      "index": ++index,
      "value": value
    };
  });
  return baseSortBy_default(result2, function(object, other) {
    return compareMultiple_default(object, other, orders);
  });
}
var baseOrderBy_default = baseOrderBy;

// node_modules/lodash-es/orderBy.js
function orderBy(collection, iteratees, orders, guard) {
  if (collection == null) {
    return [];
  }
  if (!isArray_default(iteratees)) {
    iteratees = iteratees == null ? [] : [iteratees];
  }
  orders = guard ? void 0 : orders;
  if (!isArray_default(orders)) {
    orders = orders == null ? [] : [orders];
  }
  return baseOrderBy_default(collection, iteratees, orders);
}
var orderBy_default = orderBy;

// node_modules/lodash-es/_createOver.js
function createOver(arrayFunc) {
  return flatRest_default(function(iteratees) {
    iteratees = arrayMap_default(iteratees, baseUnary_default(baseIteratee_default));
    return baseRest_default(function(args) {
      var thisArg = this;
      return arrayFunc(iteratees, function(iteratee2) {
        return apply_default(iteratee2, thisArg, args);
      });
    });
  });
}
var createOver_default = createOver;

// node_modules/lodash-es/over.js
var over = createOver_default(arrayMap_default);
var over_default = over;

// node_modules/lodash-es/_castRest.js
var castRest = baseRest_default;
var castRest_default = castRest;

// node_modules/lodash-es/overArgs.js
var nativeMin9 = Math.min;
var overArgs = castRest_default(function(func, transforms) {
  transforms = transforms.length == 1 && isArray_default(transforms[0]) ? arrayMap_default(transforms[0], baseUnary_default(baseIteratee_default)) : arrayMap_default(baseFlatten_default(transforms, 1), baseUnary_default(baseIteratee_default));
  var funcsLength = transforms.length;
  return baseRest_default(function(args) {
    var index = -1, length = nativeMin9(args.length, funcsLength);
    while (++index < length) {
      args[index] = transforms[index].call(this, args[index]);
    }
    return apply_default(func, this, args);
  });
});
var overArgs_default = overArgs;

// node_modules/lodash-es/overEvery.js
var overEvery = createOver_default(arrayEvery_default);
var overEvery_default = overEvery;

// node_modules/lodash-es/overSome.js
var overSome = createOver_default(arraySome_default);
var overSome_default = overSome;

// node_modules/lodash-es/_baseRepeat.js
var MAX_SAFE_INTEGER4 = 9007199254740991;
var nativeFloor = Math.floor;
function baseRepeat(string, n) {
  var result2 = "";
  if (!string || n < 1 || n > MAX_SAFE_INTEGER4) {
    return result2;
  }
  do {
    if (n % 2) {
      result2 += string;
    }
    n = nativeFloor(n / 2);
    if (n) {
      string += string;
    }
  } while (n);
  return result2;
}
var baseRepeat_default = baseRepeat;

// node_modules/lodash-es/_asciiSize.js
var asciiSize = baseProperty_default("length");
var asciiSize_default = asciiSize;

// node_modules/lodash-es/_unicodeSize.js
var rsAstralRange4 = "\\ud800-\\udfff";
var rsComboMarksRange5 = "\\u0300-\\u036f";
var reComboHalfMarksRange5 = "\\ufe20-\\ufe2f";
var rsComboSymbolsRange5 = "\\u20d0-\\u20ff";
var rsComboRange5 = rsComboMarksRange5 + reComboHalfMarksRange5 + rsComboSymbolsRange5;
var rsVarRange4 = "\\ufe0e\\ufe0f";
var rsAstral2 = "[" + rsAstralRange4 + "]";
var rsCombo4 = "[" + rsComboRange5 + "]";
var rsFitz3 = "\\ud83c[\\udffb-\\udfff]";
var rsModifier3 = "(?:" + rsCombo4 + "|" + rsFitz3 + ")";
var rsNonAstral3 = "[^" + rsAstralRange4 + "]";
var rsRegional3 = "(?:\\ud83c[\\udde6-\\uddff]){2}";
var rsSurrPair3 = "[\\ud800-\\udbff][\\udc00-\\udfff]";
var rsZWJ4 = "\\u200d";
var reOptMod3 = rsModifier3 + "?";
var rsOptVar3 = "[" + rsVarRange4 + "]?";
var rsOptJoin3 = "(?:" + rsZWJ4 + "(?:" + [rsNonAstral3, rsRegional3, rsSurrPair3].join("|") + ")" + rsOptVar3 + reOptMod3 + ")*";
var rsSeq3 = rsOptVar3 + reOptMod3 + rsOptJoin3;
var rsSymbol2 = "(?:" + [rsNonAstral3 + rsCombo4 + "?", rsCombo4, rsRegional3, rsSurrPair3, rsAstral2].join("|") + ")";
var reUnicode2 = RegExp(rsFitz3 + "(?=" + rsFitz3 + ")|" + rsSymbol2 + rsSeq3, "g");
function unicodeSize(string) {
  var result2 = reUnicode2.lastIndex = 0;
  while (reUnicode2.test(string)) {
    ++result2;
  }
  return result2;
}
var unicodeSize_default = unicodeSize;

// node_modules/lodash-es/_stringSize.js
function stringSize(string) {
  return hasUnicode_default(string) ? unicodeSize_default(string) : asciiSize_default(string);
}
var stringSize_default = stringSize;

// node_modules/lodash-es/_createPadding.js
var nativeCeil2 = Math.ceil;
function createPadding(length, chars) {
  chars = chars === void 0 ? " " : baseToString_default(chars);
  var charsLength = chars.length;
  if (charsLength < 2) {
    return charsLength ? baseRepeat_default(chars, length) : chars;
  }
  var result2 = baseRepeat_default(chars, nativeCeil2(length / stringSize_default(chars)));
  return hasUnicode_default(chars) ? castSlice_default(stringToArray_default(result2), 0, length).join("") : result2.slice(0, length);
}
var createPadding_default = createPadding;

// node_modules/lodash-es/pad.js
var nativeCeil3 = Math.ceil;
var nativeFloor2 = Math.floor;
function pad(string, length, chars) {
  string = toString_default(string);
  length = toInteger_default(length);
  var strLength = length ? stringSize_default(string) : 0;
  if (!length || strLength >= length) {
    return string;
  }
  var mid = (length - strLength) / 2;
  return createPadding_default(nativeFloor2(mid), chars) + string + createPadding_default(nativeCeil3(mid), chars);
}
var pad_default = pad;

// node_modules/lodash-es/padEnd.js
function padEnd(string, length, chars) {
  string = toString_default(string);
  length = toInteger_default(length);
  var strLength = length ? stringSize_default(string) : 0;
  return length && strLength < length ? string + createPadding_default(length - strLength, chars) : string;
}
var padEnd_default = padEnd;

// node_modules/lodash-es/padStart.js
function padStart(string, length, chars) {
  string = toString_default(string);
  length = toInteger_default(length);
  var strLength = length ? stringSize_default(string) : 0;
  return length && strLength < length ? createPadding_default(length - strLength, chars) + string : string;
}
var padStart_default = padStart;

// node_modules/lodash-es/parseInt.js
var reTrimStart2 = /^\s+/;
var nativeParseInt = root_default.parseInt;
function parseInt2(string, radix, guard) {
  if (guard || radix == null) {
    radix = 0;
  } else if (radix) {
    radix = +radix;
  }
  return nativeParseInt(toString_default(string).replace(reTrimStart2, ""), radix || 0);
}
var parseInt_default = parseInt2;

// node_modules/lodash-es/partial.js
var WRAP_PARTIAL_FLAG7 = 32;
var partial = baseRest_default(function(func, partials) {
  var holders = replaceHolders_default(partials, getHolder_default(partial));
  return createWrap_default(func, WRAP_PARTIAL_FLAG7, void 0, partials, holders);
});
partial.placeholder = {};
var partial_default = partial;

// node_modules/lodash-es/partialRight.js
var WRAP_PARTIAL_RIGHT_FLAG4 = 64;
var partialRight = baseRest_default(function(func, partials) {
  var holders = replaceHolders_default(partials, getHolder_default(partialRight));
  return createWrap_default(func, WRAP_PARTIAL_RIGHT_FLAG4, void 0, partials, holders);
});
partialRight.placeholder = {};
var partialRight_default = partialRight;

// node_modules/lodash-es/partition.js
var partition = createAggregator_default(function(result2, value, key) {
  result2[key ? 0 : 1].push(value);
}, function() {
  return [[], []];
});
var partition_default = partition;

// node_modules/lodash-es/_basePick.js
function basePick(object, paths) {
  return basePickBy_default(object, paths, function(value, path) {
    return hasIn_default(object, path);
  });
}
var basePick_default = basePick;

// node_modules/lodash-es/pick.js
var pick = flatRest_default(function(object, paths) {
  return object == null ? {} : basePick_default(object, paths);
});
var pick_default = pick;

// node_modules/lodash-es/plant.js
function wrapperPlant(value) {
  var result2, parent2 = this;
  while (parent2 instanceof baseLodash_default) {
    var clone2 = wrapperClone_default(parent2);
    clone2.__index__ = 0;
    clone2.__values__ = void 0;
    if (result2) {
      previous.__wrapped__ = clone2;
    } else {
      result2 = clone2;
    }
    var previous = clone2;
    parent2 = parent2.__wrapped__;
  }
  previous.__wrapped__ = value;
  return result2;
}
var plant_default = wrapperPlant;

// node_modules/lodash-es/propertyOf.js
function propertyOf(object) {
  return function(path) {
    return object == null ? void 0 : baseGet_default(object, path);
  };
}
var propertyOf_default = propertyOf;

// node_modules/lodash-es/_baseIndexOfWith.js
function baseIndexOfWith(array, value, fromIndex, comparator) {
  var index = fromIndex - 1, length = array.length;
  while (++index < length) {
    if (comparator(array[index], value)) {
      return index;
    }
  }
  return -1;
}
var baseIndexOfWith_default = baseIndexOfWith;

// node_modules/lodash-es/_basePullAll.js
var arrayProto3 = Array.prototype;
var splice2 = arrayProto3.splice;
function basePullAll(array, values2, iteratee2, comparator) {
  var indexOf2 = comparator ? baseIndexOfWith_default : baseIndexOf_default, index = -1, length = values2.length, seen = array;
  if (array === values2) {
    values2 = copyArray_default(values2);
  }
  if (iteratee2) {
    seen = arrayMap_default(array, baseUnary_default(iteratee2));
  }
  while (++index < length) {
    var fromIndex = 0, value = values2[index], computed = iteratee2 ? iteratee2(value) : value;
    while ((fromIndex = indexOf2(seen, computed, fromIndex, comparator)) > -1) {
      if (seen !== array) {
        splice2.call(seen, fromIndex, 1);
      }
      splice2.call(array, fromIndex, 1);
    }
  }
  return array;
}
var basePullAll_default = basePullAll;

// node_modules/lodash-es/pullAll.js
function pullAll(array, values2) {
  return array && array.length && values2 && values2.length ? basePullAll_default(array, values2) : array;
}
var pullAll_default = pullAll;

// node_modules/lodash-es/pull.js
var pull = baseRest_default(pullAll_default);
var pull_default = pull;

// node_modules/lodash-es/pullAllBy.js
function pullAllBy(array, values2, iteratee2) {
  return array && array.length && values2 && values2.length ? basePullAll_default(array, values2, baseIteratee_default(iteratee2, 2)) : array;
}
var pullAllBy_default = pullAllBy;

// node_modules/lodash-es/pullAllWith.js
function pullAllWith(array, values2, comparator) {
  return array && array.length && values2 && values2.length ? basePullAll_default(array, values2, void 0, comparator) : array;
}
var pullAllWith_default = pullAllWith;

// node_modules/lodash-es/_basePullAt.js
var arrayProto4 = Array.prototype;
var splice3 = arrayProto4.splice;
function basePullAt(array, indexes) {
  var length = array ? indexes.length : 0, lastIndex = length - 1;
  while (length--) {
    var index = indexes[length];
    if (length == lastIndex || index !== previous) {
      var previous = index;
      if (isIndex_default(index)) {
        splice3.call(array, index, 1);
      } else {
        baseUnset_default(array, index);
      }
    }
  }
  return array;
}
var basePullAt_default = basePullAt;

// node_modules/lodash-es/pullAt.js
var pullAt = flatRest_default(function(array, indexes) {
  var length = array == null ? 0 : array.length, result2 = baseAt_default(array, indexes);
  basePullAt_default(array, arrayMap_default(indexes, function(index) {
    return isIndex_default(index, length) ? +index : index;
  }).sort(compareAscending_default));
  return result2;
});
var pullAt_default = pullAt;

// node_modules/lodash-es/_baseRandom.js
var nativeFloor3 = Math.floor;
var nativeRandom = Math.random;
function baseRandom(lower, upper) {
  return lower + nativeFloor3(nativeRandom() * (upper - lower + 1));
}
var baseRandom_default = baseRandom;

// node_modules/lodash-es/random.js
var freeParseFloat = parseFloat;
var nativeMin10 = Math.min;
var nativeRandom2 = Math.random;
function random(lower, upper, floating) {
  if (floating && typeof floating != "boolean" && isIterateeCall_default(lower, upper, floating)) {
    upper = floating = void 0;
  }
  if (floating === void 0) {
    if (typeof upper == "boolean") {
      floating = upper;
      upper = void 0;
    } else if (typeof lower == "boolean") {
      floating = lower;
      lower = void 0;
    }
  }
  if (lower === void 0 && upper === void 0) {
    lower = 0;
    upper = 1;
  } else {
    lower = toFinite_default(lower);
    if (upper === void 0) {
      upper = lower;
      lower = 0;
    } else {
      upper = toFinite_default(upper);
    }
  }
  if (lower > upper) {
    var temp = lower;
    lower = upper;
    upper = temp;
  }
  if (floating || lower % 1 || upper % 1) {
    var rand = nativeRandom2();
    return nativeMin10(lower + rand * (upper - lower + freeParseFloat("1e-" + ((rand + "").length - 1))), upper);
  }
  return baseRandom_default(lower, upper);
}
var random_default = random;

// node_modules/lodash-es/_baseRange.js
var nativeCeil4 = Math.ceil;
var nativeMax13 = Math.max;
function baseRange(start, end, step, fromRight) {
  var index = -1, length = nativeMax13(nativeCeil4((end - start) / (step || 1)), 0), result2 = Array(length);
  while (length--) {
    result2[fromRight ? length : ++index] = start;
    start += step;
  }
  return result2;
}
var baseRange_default = baseRange;

// node_modules/lodash-es/_createRange.js
function createRange(fromRight) {
  return function(start, end, step) {
    if (step && typeof step != "number" && isIterateeCall_default(start, end, step)) {
      end = step = void 0;
    }
    start = toFinite_default(start);
    if (end === void 0) {
      end = start;
      start = 0;
    } else {
      end = toFinite_default(end);
    }
    step = step === void 0 ? start < end ? 1 : -1 : toFinite_default(step);
    return baseRange_default(start, end, step, fromRight);
  };
}
var createRange_default = createRange;

// node_modules/lodash-es/range.js
var range = createRange_default();
var range_default = range;

// node_modules/lodash-es/rangeRight.js
var rangeRight = createRange_default(true);
var rangeRight_default = rangeRight;

// node_modules/lodash-es/rearg.js
var WRAP_REARG_FLAG4 = 256;
var rearg = flatRest_default(function(func, indexes) {
  return createWrap_default(func, WRAP_REARG_FLAG4, void 0, void 0, void 0, indexes);
});
var rearg_default = rearg;

// node_modules/lodash-es/_baseReduce.js
function baseReduce(collection, iteratee2, accumulator, initAccum, eachFunc) {
  eachFunc(collection, function(value, index, collection2) {
    accumulator = initAccum ? (initAccum = false, value) : iteratee2(accumulator, value, index, collection2);
  });
  return accumulator;
}
var baseReduce_default = baseReduce;

// node_modules/lodash-es/reduce.js
function reduce(collection, iteratee2, accumulator) {
  var func = isArray_default(collection) ? arrayReduce_default : baseReduce_default, initAccum = arguments.length < 3;
  return func(collection, baseIteratee_default(iteratee2, 4), accumulator, initAccum, baseEach_default);
}
var reduce_default = reduce;

// node_modules/lodash-es/_arrayReduceRight.js
function arrayReduceRight(array, iteratee2, accumulator, initAccum) {
  var length = array == null ? 0 : array.length;
  if (initAccum && length) {
    accumulator = array[--length];
  }
  while (length--) {
    accumulator = iteratee2(accumulator, array[length], length, array);
  }
  return accumulator;
}
var arrayReduceRight_default = arrayReduceRight;

// node_modules/lodash-es/reduceRight.js
function reduceRight(collection, iteratee2, accumulator) {
  var func = isArray_default(collection) ? arrayReduceRight_default : baseReduce_default, initAccum = arguments.length < 3;
  return func(collection, baseIteratee_default(iteratee2, 4), accumulator, initAccum, baseEachRight_default);
}
var reduceRight_default = reduceRight;

// node_modules/lodash-es/reject.js
function reject(collection, predicate) {
  var func = isArray_default(collection) ? arrayFilter_default : baseFilter_default;
  return func(collection, negate_default(baseIteratee_default(predicate, 3)));
}
var reject_default = reject;

// node_modules/lodash-es/remove.js
function remove(array, predicate) {
  var result2 = [];
  if (!(array && array.length)) {
    return result2;
  }
  var index = -1, indexes = [], length = array.length;
  predicate = baseIteratee_default(predicate, 3);
  while (++index < length) {
    var value = array[index];
    if (predicate(value, index, array)) {
      result2.push(value);
      indexes.push(index);
    }
  }
  basePullAt_default(array, indexes);
  return result2;
}
var remove_default = remove;

// node_modules/lodash-es/repeat.js
function repeat(string, n, guard) {
  if (guard ? isIterateeCall_default(string, n, guard) : n === void 0) {
    n = 1;
  } else {
    n = toInteger_default(n);
  }
  return baseRepeat_default(toString_default(string), n);
}
var repeat_default = repeat;

// node_modules/lodash-es/replace.js
function replace() {
  var args = arguments, string = toString_default(args[0]);
  return args.length < 3 ? string : string.replace(args[1], args[2]);
}
var replace_default = replace;

// node_modules/lodash-es/rest.js
var FUNC_ERROR_TEXT10 = "Expected a function";
function rest(func, start) {
  if (typeof func != "function") {
    throw new TypeError(FUNC_ERROR_TEXT10);
  }
  start = start === void 0 ? start : toInteger_default(start);
  return baseRest_default(func, start);
}
var rest_default = rest;

// node_modules/lodash-es/result.js
function result(object, path, defaultValue) {
  path = castPath_default(path, object);
  var index = -1, length = path.length;
  if (!length) {
    length = 1;
    object = void 0;
  }
  while (++index < length) {
    var value = object == null ? void 0 : object[toKey_default(path[index])];
    if (value === void 0) {
      index = length;
      value = defaultValue;
    }
    object = isFunction_default(value) ? value.call(object) : value;
  }
  return object;
}
var result_default = result;

// node_modules/lodash-es/reverse.js
var arrayProto5 = Array.prototype;
var nativeReverse = arrayProto5.reverse;
function reverse(array) {
  return array == null ? array : nativeReverse.call(array);
}
var reverse_default = reverse;

// node_modules/lodash-es/round.js
var round = createRound_default("round");
var round_default = round;

// node_modules/lodash-es/_arraySample.js
function arraySample(array) {
  var length = array.length;
  return length ? array[baseRandom_default(0, length - 1)] : void 0;
}
var arraySample_default = arraySample;

// node_modules/lodash-es/_baseSample.js
function baseSample(collection) {
  return arraySample_default(values_default(collection));
}
var baseSample_default = baseSample;

// node_modules/lodash-es/sample.js
function sample(collection) {
  var func = isArray_default(collection) ? arraySample_default : baseSample_default;
  return func(collection);
}
var sample_default = sample;

// node_modules/lodash-es/_shuffleSelf.js
function shuffleSelf(array, size2) {
  var index = -1, length = array.length, lastIndex = length - 1;
  size2 = size2 === void 0 ? length : size2;
  while (++index < size2) {
    var rand = baseRandom_default(index, lastIndex), value = array[rand];
    array[rand] = array[index];
    array[index] = value;
  }
  array.length = size2;
  return array;
}
var shuffleSelf_default = shuffleSelf;

// node_modules/lodash-es/_arraySampleSize.js
function arraySampleSize(array, n) {
  return shuffleSelf_default(copyArray_default(array), baseClamp_default(n, 0, array.length));
}
var arraySampleSize_default = arraySampleSize;

// node_modules/lodash-es/_baseSampleSize.js
function baseSampleSize(collection, n) {
  var array = values_default(collection);
  return shuffleSelf_default(array, baseClamp_default(n, 0, array.length));
}
var baseSampleSize_default = baseSampleSize;

// node_modules/lodash-es/sampleSize.js
function sampleSize(collection, n, guard) {
  if (guard ? isIterateeCall_default(collection, n, guard) : n === void 0) {
    n = 1;
  } else {
    n = toInteger_default(n);
  }
  var func = isArray_default(collection) ? arraySampleSize_default : baseSampleSize_default;
  return func(collection, n);
}
var sampleSize_default = sampleSize;

// node_modules/lodash-es/set.js
function set(object, path, value) {
  return object == null ? object : baseSet_default(object, path, value);
}
var set_default = set;

// node_modules/lodash-es/setWith.js
function setWith(object, path, value, customizer) {
  customizer = typeof customizer == "function" ? customizer : void 0;
  return object == null ? object : baseSet_default(object, path, value, customizer);
}
var setWith_default = setWith;

// node_modules/lodash-es/_arrayShuffle.js
function arrayShuffle(array) {
  return shuffleSelf_default(copyArray_default(array));
}
var arrayShuffle_default = arrayShuffle;

// node_modules/lodash-es/_baseShuffle.js
function baseShuffle(collection) {
  return shuffleSelf_default(values_default(collection));
}
var baseShuffle_default = baseShuffle;

// node_modules/lodash-es/shuffle.js
function shuffle(collection) {
  var func = isArray_default(collection) ? arrayShuffle_default : baseShuffle_default;
  return func(collection);
}
var shuffle_default = shuffle;

// node_modules/lodash-es/size.js
var mapTag10 = "[object Map]";
var setTag10 = "[object Set]";
function size(collection) {
  if (collection == null) {
    return 0;
  }
  if (isArrayLike_default(collection)) {
    return isString_default(collection) ? stringSize_default(collection) : collection.length;
  }
  var tag = getTag_default(collection);
  if (tag == mapTag10 || tag == setTag10) {
    return collection.size;
  }
  return baseKeys_default(collection).length;
}
var size_default = size;

// node_modules/lodash-es/slice.js
function slice(array, start, end) {
  var length = array == null ? 0 : array.length;
  if (!length) {
    return [];
  }
  if (end && typeof end != "number" && isIterateeCall_default(array, start, end)) {
    start = 0;
    end = length;
  } else {
    start = start == null ? 0 : toInteger_default(start);
    end = end === void 0 ? length : toInteger_default(end);
  }
  return baseSlice_default(array, start, end);
}
var slice_default = slice;

// node_modules/lodash-es/snakeCase.js
var snakeCase = createCompounder_default(function(result2, word, index) {
  return result2 + (index ? "_" : "") + word.toLowerCase();
});
var snakeCase_default = snakeCase;

// node_modules/lodash-es/_baseSome.js
function baseSome(collection, predicate) {
  var result2;
  baseEach_default(collection, function(value, index, collection2) {
    result2 = predicate(value, index, collection2);
    return !result2;
  });
  return !!result2;
}
var baseSome_default = baseSome;

// node_modules/lodash-es/some.js
function some(collection, predicate, guard) {
  var func = isArray_default(collection) ? arraySome_default : baseSome_default;
  if (guard && isIterateeCall_default(collection, predicate, guard)) {
    predicate = void 0;
  }
  return func(collection, baseIteratee_default(predicate, 3));
}
var some_default = some;

// node_modules/lodash-es/sortBy.js
var sortBy = baseRest_default(function(collection, iteratees) {
  if (collection == null) {
    return [];
  }
  var length = iteratees.length;
  if (length > 1 && isIterateeCall_default(collection, iteratees[0], iteratees[1])) {
    iteratees = [];
  } else if (length > 2 && isIterateeCall_default(iteratees[0], iteratees[1], iteratees[2])) {
    iteratees = [iteratees[0]];
  }
  return baseOrderBy_default(collection, baseFlatten_default(iteratees, 1), []);
});
var sortBy_default = sortBy;

// node_modules/lodash-es/_baseSortedIndexBy.js
var MAX_ARRAY_LENGTH3 = 4294967295;
var MAX_ARRAY_INDEX = MAX_ARRAY_LENGTH3 - 1;
var nativeFloor4 = Math.floor;
var nativeMin11 = Math.min;
function baseSortedIndexBy(array, value, iteratee2, retHighest) {
  var low = 0, high = array == null ? 0 : array.length;
  if (high === 0) {
    return 0;
  }
  value = iteratee2(value);
  var valIsNaN = value !== value, valIsNull = value === null, valIsSymbol = isSymbol_default(value), valIsUndefined = value === void 0;
  while (low < high) {
    var mid = nativeFloor4((low + high) / 2), computed = iteratee2(array[mid]), othIsDefined = computed !== void 0, othIsNull = computed === null, othIsReflexive = computed === computed, othIsSymbol = isSymbol_default(computed);
    if (valIsNaN) {
      var setLow = retHighest || othIsReflexive;
    } else if (valIsUndefined) {
      setLow = othIsReflexive && (retHighest || othIsDefined);
    } else if (valIsNull) {
      setLow = othIsReflexive && othIsDefined && (retHighest || !othIsNull);
    } else if (valIsSymbol) {
      setLow = othIsReflexive && othIsDefined && !othIsNull && (retHighest || !othIsSymbol);
    } else if (othIsNull || othIsSymbol) {
      setLow = false;
    } else {
      setLow = retHighest ? computed <= value : computed < value;
    }
    if (setLow) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }
  return nativeMin11(high, MAX_ARRAY_INDEX);
}
var baseSortedIndexBy_default = baseSortedIndexBy;

// node_modules/lodash-es/_baseSortedIndex.js
var MAX_ARRAY_LENGTH4 = 4294967295;
var HALF_MAX_ARRAY_LENGTH = MAX_ARRAY_LENGTH4 >>> 1;
function baseSortedIndex(array, value, retHighest) {
  var low = 0, high = array == null ? low : array.length;
  if (typeof value == "number" && value === value && high <= HALF_MAX_ARRAY_LENGTH) {
    while (low < high) {
      var mid = low + high >>> 1, computed = array[mid];
      if (computed !== null && !isSymbol_default(computed) && (retHighest ? computed <= value : computed < value)) {
        low = mid + 1;
      } else {
        high = mid;
      }
    }
    return high;
  }
  return baseSortedIndexBy_default(array, value, identity_default, retHighest);
}
var baseSortedIndex_default = baseSortedIndex;

// node_modules/lodash-es/sortedIndex.js
function sortedIndex(array, value) {
  return baseSortedIndex_default(array, value);
}
var sortedIndex_default = sortedIndex;

// node_modules/lodash-es/sortedIndexBy.js
function sortedIndexBy(array, value, iteratee2) {
  return baseSortedIndexBy_default(array, value, baseIteratee_default(iteratee2, 2));
}
var sortedIndexBy_default = sortedIndexBy;

// node_modules/lodash-es/sortedIndexOf.js
function sortedIndexOf(array, value) {
  var length = array == null ? 0 : array.length;
  if (length) {
    var index = baseSortedIndex_default(array, value);
    if (index < length && eq_default(array[index], value)) {
      return index;
    }
  }
  return -1;
}
var sortedIndexOf_default = sortedIndexOf;

// node_modules/lodash-es/sortedLastIndex.js
function sortedLastIndex(array, value) {
  return baseSortedIndex_default(array, value, true);
}
var sortedLastIndex_default = sortedLastIndex;

// node_modules/lodash-es/sortedLastIndexBy.js
function sortedLastIndexBy(array, value, iteratee2) {
  return baseSortedIndexBy_default(array, value, baseIteratee_default(iteratee2, 2), true);
}
var sortedLastIndexBy_default = sortedLastIndexBy;

// node_modules/lodash-es/sortedLastIndexOf.js
function sortedLastIndexOf(array, value) {
  var length = array == null ? 0 : array.length;
  if (length) {
    var index = baseSortedIndex_default(array, value, true) - 1;
    if (eq_default(array[index], value)) {
      return index;
    }
  }
  return -1;
}
var sortedLastIndexOf_default = sortedLastIndexOf;

// node_modules/lodash-es/_baseSortedUniq.js
function baseSortedUniq(array, iteratee2) {
  var index = -1, length = array.length, resIndex = 0, result2 = [];
  while (++index < length) {
    var value = array[index], computed = iteratee2 ? iteratee2(value) : value;
    if (!index || !eq_default(computed, seen)) {
      var seen = computed;
      result2[resIndex++] = value === 0 ? 0 : value;
    }
  }
  return result2;
}
var baseSortedUniq_default = baseSortedUniq;

// node_modules/lodash-es/sortedUniq.js
function sortedUniq(array) {
  return array && array.length ? baseSortedUniq_default(array) : [];
}
var sortedUniq_default = sortedUniq;

// node_modules/lodash-es/sortedUniqBy.js
function sortedUniqBy(array, iteratee2) {
  return array && array.length ? baseSortedUniq_default(array, baseIteratee_default(iteratee2, 2)) : [];
}
var sortedUniqBy_default = sortedUniqBy;

// node_modules/lodash-es/split.js
var MAX_ARRAY_LENGTH5 = 4294967295;
function split(string, separator, limit) {
  if (limit && typeof limit != "number" && isIterateeCall_default(string, separator, limit)) {
    separator = limit = void 0;
  }
  limit = limit === void 0 ? MAX_ARRAY_LENGTH5 : limit >>> 0;
  if (!limit) {
    return [];
  }
  string = toString_default(string);
  if (string && (typeof separator == "string" || separator != null && !isRegExp_default(separator))) {
    separator = baseToString_default(separator);
    if (!separator && hasUnicode_default(string)) {
      return castSlice_default(stringToArray_default(string), 0, limit);
    }
  }
  return string.split(separator, limit);
}
var split_default = split;

// node_modules/lodash-es/spread.js
var FUNC_ERROR_TEXT11 = "Expected a function";
var nativeMax14 = Math.max;
function spread(func, start) {
  if (typeof func != "function") {
    throw new TypeError(FUNC_ERROR_TEXT11);
  }
  start = start == null ? 0 : nativeMax14(toInteger_default(start), 0);
  return baseRest_default(function(args) {
    var array = args[start], otherArgs = castSlice_default(args, 0, start);
    if (array) {
      arrayPush_default(otherArgs, array);
    }
    return apply_default(func, this, otherArgs);
  });
}
var spread_default = spread;

// node_modules/lodash-es/startCase.js
var startCase = createCompounder_default(function(result2, word, index) {
  return result2 + (index ? " " : "") + upperFirst_default(word);
});
var startCase_default = startCase;

// node_modules/lodash-es/startsWith.js
function startsWith(string, target, position) {
  string = toString_default(string);
  position = position == null ? 0 : baseClamp_default(toInteger_default(position), 0, string.length);
  target = baseToString_default(target);
  return string.slice(position, position + target.length) == target;
}
var startsWith_default = startsWith;

// node_modules/lodash-es/stubObject.js
function stubObject() {
  return {};
}
var stubObject_default = stubObject;

// node_modules/lodash-es/stubString.js
function stubString() {
  return "";
}
var stubString_default = stubString;

// node_modules/lodash-es/stubTrue.js
function stubTrue() {
  return true;
}
var stubTrue_default = stubTrue;

// node_modules/lodash-es/subtract.js
var subtract = createMathOperation_default(function(minuend, subtrahend) {
  return minuend - subtrahend;
}, 0);
var subtract_default = subtract;

// node_modules/lodash-es/sum.js
function sum(array) {
  return array && array.length ? baseSum_default(array, identity_default) : 0;
}
var sum_default = sum;

// node_modules/lodash-es/sumBy.js
function sumBy(array, iteratee2) {
  return array && array.length ? baseSum_default(array, baseIteratee_default(iteratee2, 2)) : 0;
}
var sumBy_default = sumBy;

// node_modules/lodash-es/tail.js
function tail(array) {
  var length = array == null ? 0 : array.length;
  return length ? baseSlice_default(array, 1, length) : [];
}
var tail_default = tail;

// node_modules/lodash-es/take.js
function take(array, n, guard) {
  if (!(array && array.length)) {
    return [];
  }
  n = guard || n === void 0 ? 1 : toInteger_default(n);
  return baseSlice_default(array, 0, n < 0 ? 0 : n);
}
var take_default = take;

// node_modules/lodash-es/takeRight.js
function takeRight(array, n, guard) {
  var length = array == null ? 0 : array.length;
  if (!length) {
    return [];
  }
  n = guard || n === void 0 ? 1 : toInteger_default(n);
  n = length - n;
  return baseSlice_default(array, n < 0 ? 0 : n, length);
}
var takeRight_default = takeRight;

// node_modules/lodash-es/takeRightWhile.js
function takeRightWhile(array, predicate) {
  return array && array.length ? baseWhile_default(array, baseIteratee_default(predicate, 3), false, true) : [];
}
var takeRightWhile_default = takeRightWhile;

// node_modules/lodash-es/takeWhile.js
function takeWhile(array, predicate) {
  return array && array.length ? baseWhile_default(array, baseIteratee_default(predicate, 3)) : [];
}
var takeWhile_default = takeWhile;

// node_modules/lodash-es/tap.js
function tap(value, interceptor) {
  interceptor(value);
  return value;
}
var tap_default = tap;

// node_modules/lodash-es/_customDefaultsAssignIn.js
var objectProto27 = Object.prototype;
var hasOwnProperty23 = objectProto27.hasOwnProperty;
function customDefaultsAssignIn(objValue, srcValue, key, object) {
  if (objValue === void 0 || eq_default(objValue, objectProto27[key]) && !hasOwnProperty23.call(object, key)) {
    return srcValue;
  }
  return objValue;
}
var customDefaultsAssignIn_default = customDefaultsAssignIn;

// node_modules/lodash-es/_escapeStringChar.js
var stringEscapes = {
  "\\": "\\",
  "'": "'",
  "\n": "n",
  "\r": "r",
  "\u2028": "u2028",
  "\u2029": "u2029"
};
function escapeStringChar(chr) {
  return "\\" + stringEscapes[chr];
}
var escapeStringChar_default = escapeStringChar;

// node_modules/lodash-es/_reInterpolate.js
var reInterpolate = /<%=([\s\S]+?)%>/g;
var reInterpolate_default = reInterpolate;

// node_modules/lodash-es/_reEscape.js
var reEscape = /<%-([\s\S]+?)%>/g;
var reEscape_default = reEscape;

// node_modules/lodash-es/_reEvaluate.js
var reEvaluate = /<%([\s\S]+?)%>/g;
var reEvaluate_default = reEvaluate;

// node_modules/lodash-es/templateSettings.js
var templateSettings = {
  /**
   * Used to detect `data` property values to be HTML-escaped.
   *
   * @memberOf _.templateSettings
   * @type {RegExp}
   */
  "escape": reEscape_default,
  /**
   * Used to detect code to be evaluated.
   *
   * @memberOf _.templateSettings
   * @type {RegExp}
   */
  "evaluate": reEvaluate_default,
  /**
   * Used to detect `data` property values to inject.
   *
   * @memberOf _.templateSettings
   * @type {RegExp}
   */
  "interpolate": reInterpolate_default,
  /**
   * Used to reference the data object in the template text.
   *
   * @memberOf _.templateSettings
   * @type {string}
   */
  "variable": "",
  /**
   * Used to import variables into the compiled template.
   *
   * @memberOf _.templateSettings
   * @type {Object}
   */
  "imports": {
    /**
     * A reference to the `lodash` function.
     *
     * @memberOf _.templateSettings.imports
     * @type {Function}
     */
    "_": {
      "escape": escape_default
    }
  }
};
var templateSettings_default = templateSettings;

// node_modules/lodash-es/template.js
var INVALID_TEMPL_VAR_ERROR_TEXT = "Invalid `variable` option passed into `_.template`";
var reEmptyStringLeading = /\b__p \+= '';/g;
var reEmptyStringMiddle = /\b(__p \+=) '' \+/g;
var reEmptyStringTrailing = /(__e\(.*?\)|\b__t\)) \+\n'';/g;
var reForbiddenIdentifierChars = /[()=,{}\[\]\/\s]/;
var reEsTemplate = /\$\{([^\\}]*(?:\\.[^\\}]*)*)\}/g;
var reNoMatch = /($^)/;
var reUnescapedString = /['\n\r\u2028\u2029\\]/g;
var objectProto28 = Object.prototype;
var hasOwnProperty24 = objectProto28.hasOwnProperty;
function template(string, options, guard) {
  var settings = templateSettings_default.imports._.templateSettings || templateSettings_default;
  if (guard && isIterateeCall_default(string, options, guard)) {
    options = void 0;
  }
  string = toString_default(string);
  options = assignInWith_default({}, options, settings, customDefaultsAssignIn_default);
  var imports = assignInWith_default({}, options.imports, settings.imports, customDefaultsAssignIn_default), importsKeys = keys_default(imports), importsValues = baseValues_default(imports, importsKeys);
  var isEscaping, isEvaluating, index = 0, interpolate = options.interpolate || reNoMatch, source = "__p += '";
  var reDelimiters = RegExp((options.escape || reNoMatch).source + "|" + interpolate.source + "|" + (interpolate === reInterpolate_default ? reEsTemplate : reNoMatch).source + "|" + (options.evaluate || reNoMatch).source + "|$", "g");
  var sourceURL = hasOwnProperty24.call(options, "sourceURL") ? "//# sourceURL=" + (options.sourceURL + "").replace(/\s/g, " ") + "\n" : "";
  string.replace(reDelimiters, function(match2, escapeValue, interpolateValue, esTemplateValue, evaluateValue, offset) {
    interpolateValue || (interpolateValue = esTemplateValue);
    source += string.slice(index, offset).replace(reUnescapedString, escapeStringChar_default);
    if (escapeValue) {
      isEscaping = true;
      source += "' +\n__e(" + escapeValue + ") +\n'";
    }
    if (evaluateValue) {
      isEvaluating = true;
      source += "';\n" + evaluateValue + ";\n__p += '";
    }
    if (interpolateValue) {
      source += "' +\n((__t = (" + interpolateValue + ")) == null ? '' : __t) +\n'";
    }
    index = offset + match2.length;
    return match2;
  });
  source += "';\n";
  var variable = hasOwnProperty24.call(options, "variable") && options.variable;
  if (!variable) {
    source = "with (obj) {\n" + source + "\n}\n";
  } else if (reForbiddenIdentifierChars.test(variable)) {
    throw new Error(INVALID_TEMPL_VAR_ERROR_TEXT);
  }
  source = (isEvaluating ? source.replace(reEmptyStringLeading, "") : source).replace(reEmptyStringMiddle, "$1").replace(reEmptyStringTrailing, "$1;");
  source = "function(" + (variable || "obj") + ") {\n" + (variable ? "" : "obj || (obj = {});\n") + "var __t, __p = ''" + (isEscaping ? ", __e = _.escape" : "") + (isEvaluating ? ", __j = Array.prototype.join;\nfunction print() { __p += __j.call(arguments, '') }\n" : ";\n") + source + "return __p\n}";
  var result2 = attempt_default(function() {
    return Function(importsKeys, sourceURL + "return " + source).apply(void 0, importsValues);
  });
  result2.source = source;
  if (isError_default(result2)) {
    throw result2;
  }
  return result2;
}
var template_default = template;

// node_modules/lodash-es/throttle.js
var FUNC_ERROR_TEXT12 = "Expected a function";
function throttle(func, wait, options) {
  var leading = true, trailing = true;
  if (typeof func != "function") {
    throw new TypeError(FUNC_ERROR_TEXT12);
  }
  if (isObject_default(options)) {
    leading = "leading" in options ? !!options.leading : leading;
    trailing = "trailing" in options ? !!options.trailing : trailing;
  }
  return debounce_default(func, wait, {
    "leading": leading,
    "maxWait": wait,
    "trailing": trailing
  });
}
var throttle_default = throttle;

// node_modules/lodash-es/thru.js
function thru(value, interceptor) {
  return interceptor(value);
}
var thru_default = thru;

// node_modules/lodash-es/times.js
var MAX_SAFE_INTEGER5 = 9007199254740991;
var MAX_ARRAY_LENGTH6 = 4294967295;
var nativeMin12 = Math.min;
function times(n, iteratee2) {
  n = toInteger_default(n);
  if (n < 1 || n > MAX_SAFE_INTEGER5) {
    return [];
  }
  var index = MAX_ARRAY_LENGTH6, length = nativeMin12(n, MAX_ARRAY_LENGTH6);
  iteratee2 = castFunction_default(iteratee2);
  n -= MAX_ARRAY_LENGTH6;
  var result2 = baseTimes_default(length, iteratee2);
  while (++index < n) {
    iteratee2(index);
  }
  return result2;
}
var times_default = times;

// node_modules/lodash-es/toIterator.js
function wrapperToIterator() {
  return this;
}
var toIterator_default = wrapperToIterator;

// node_modules/lodash-es/_baseWrapperValue.js
function baseWrapperValue(value, actions) {
  var result2 = value;
  if (result2 instanceof LazyWrapper_default) {
    result2 = result2.value();
  }
  return arrayReduce_default(actions, function(result3, action) {
    return action.func.apply(action.thisArg, arrayPush_default([result3], action.args));
  }, result2);
}
var baseWrapperValue_default = baseWrapperValue;

// node_modules/lodash-es/wrapperValue.js
function wrapperValue() {
  return baseWrapperValue_default(this.__wrapped__, this.__actions__);
}
var wrapperValue_default = wrapperValue;

// node_modules/lodash-es/toLower.js
function toLower(value) {
  return toString_default(value).toLowerCase();
}
var toLower_default = toLower;

// node_modules/lodash-es/toPath.js
function toPath(value) {
  if (isArray_default(value)) {
    return arrayMap_default(value, toKey_default);
  }
  return isSymbol_default(value) ? [value] : copyArray_default(stringToPath_default(toString_default(value)));
}
var toPath_default = toPath;

// node_modules/lodash-es/toSafeInteger.js
var MAX_SAFE_INTEGER6 = 9007199254740991;
function toSafeInteger(value) {
  return value ? baseClamp_default(toInteger_default(value), -MAX_SAFE_INTEGER6, MAX_SAFE_INTEGER6) : value === 0 ? value : 0;
}
var toSafeInteger_default = toSafeInteger;

// node_modules/lodash-es/toUpper.js
function toUpper(value) {
  return toString_default(value).toUpperCase();
}
var toUpper_default = toUpper;

// node_modules/lodash-es/transform.js
function transform(object, iteratee2, accumulator) {
  var isArr = isArray_default(object), isArrLike = isArr || isBuffer_default(object) || isTypedArray_default(object);
  iteratee2 = baseIteratee_default(iteratee2, 4);
  if (accumulator == null) {
    var Ctor = object && object.constructor;
    if (isArrLike) {
      accumulator = isArr ? new Ctor() : [];
    } else if (isObject_default(object)) {
      accumulator = isFunction_default(Ctor) ? baseCreate_default(getPrototype_default(object)) : {};
    } else {
      accumulator = {};
    }
  }
  (isArrLike ? arrayEach_default : baseForOwn_default)(object, function(value, index, object2) {
    return iteratee2(accumulator, value, index, object2);
  });
  return accumulator;
}
var transform_default = transform;

// node_modules/lodash-es/_charsEndIndex.js
function charsEndIndex(strSymbols, chrSymbols) {
  var index = strSymbols.length;
  while (index-- && baseIndexOf_default(chrSymbols, strSymbols[index], 0) > -1) {
  }
  return index;
}
var charsEndIndex_default = charsEndIndex;

// node_modules/lodash-es/_charsStartIndex.js
function charsStartIndex(strSymbols, chrSymbols) {
  var index = -1, length = strSymbols.length;
  while (++index < length && baseIndexOf_default(chrSymbols, strSymbols[index], 0) > -1) {
  }
  return index;
}
var charsStartIndex_default = charsStartIndex;

// node_modules/lodash-es/trim.js
function trim(string, chars, guard) {
  string = toString_default(string);
  if (string && (guard || chars === void 0)) {
    return baseTrim_default(string);
  }
  if (!string || !(chars = baseToString_default(chars))) {
    return string;
  }
  var strSymbols = stringToArray_default(string), chrSymbols = stringToArray_default(chars), start = charsStartIndex_default(strSymbols, chrSymbols), end = charsEndIndex_default(strSymbols, chrSymbols) + 1;
  return castSlice_default(strSymbols, start, end).join("");
}
var trim_default = trim;

// node_modules/lodash-es/trimEnd.js
function trimEnd(string, chars, guard) {
  string = toString_default(string);
  if (string && (guard || chars === void 0)) {
    return string.slice(0, trimmedEndIndex_default(string) + 1);
  }
  if (!string || !(chars = baseToString_default(chars))) {
    return string;
  }
  var strSymbols = stringToArray_default(string), end = charsEndIndex_default(strSymbols, stringToArray_default(chars)) + 1;
  return castSlice_default(strSymbols, 0, end).join("");
}
var trimEnd_default = trimEnd;

// node_modules/lodash-es/trimStart.js
var reTrimStart3 = /^\s+/;
function trimStart(string, chars, guard) {
  string = toString_default(string);
  if (string && (guard || chars === void 0)) {
    return string.replace(reTrimStart3, "");
  }
  if (!string || !(chars = baseToString_default(chars))) {
    return string;
  }
  var strSymbols = stringToArray_default(string), start = charsStartIndex_default(strSymbols, stringToArray_default(chars));
  return castSlice_default(strSymbols, start).join("");
}
var trimStart_default = trimStart;

// node_modules/lodash-es/truncate.js
var DEFAULT_TRUNC_LENGTH = 30;
var DEFAULT_TRUNC_OMISSION = "...";
var reFlags2 = /\w*$/;
function truncate(string, options) {
  var length = DEFAULT_TRUNC_LENGTH, omission = DEFAULT_TRUNC_OMISSION;
  if (isObject_default(options)) {
    var separator = "separator" in options ? options.separator : separator;
    length = "length" in options ? toInteger_default(options.length) : length;
    omission = "omission" in options ? baseToString_default(options.omission) : omission;
  }
  string = toString_default(string);
  var strLength = string.length;
  if (hasUnicode_default(string)) {
    var strSymbols = stringToArray_default(string);
    strLength = strSymbols.length;
  }
  if (length >= strLength) {
    return string;
  }
  var end = length - stringSize_default(omission);
  if (end < 1) {
    return omission;
  }
  var result2 = strSymbols ? castSlice_default(strSymbols, 0, end).join("") : string.slice(0, end);
  if (separator === void 0) {
    return result2 + omission;
  }
  if (strSymbols) {
    end += result2.length - end;
  }
  if (isRegExp_default(separator)) {
    if (string.slice(end).search(separator)) {
      var match2, substring = result2;
      if (!separator.global) {
        separator = RegExp(separator.source, toString_default(reFlags2.exec(separator)) + "g");
      }
      separator.lastIndex = 0;
      while (match2 = separator.exec(substring)) {
        var newEnd = match2.index;
      }
      result2 = result2.slice(0, newEnd === void 0 ? end : newEnd);
    }
  } else if (string.indexOf(baseToString_default(separator), end) != end) {
    var index = result2.lastIndexOf(separator);
    if (index > -1) {
      result2 = result2.slice(0, index);
    }
  }
  return result2 + omission;
}
var truncate_default = truncate;

// node_modules/lodash-es/unary.js
function unary(func) {
  return ary_default(func, 1);
}
var unary_default = unary;

// node_modules/lodash-es/_unescapeHtmlChar.js
var htmlUnescapes = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&#39;": "'"
};
var unescapeHtmlChar = basePropertyOf_default(htmlUnescapes);
var unescapeHtmlChar_default = unescapeHtmlChar;

// node_modules/lodash-es/unescape.js
var reEscapedHtml = /&(?:amp|lt|gt|quot|#39);/g;
var reHasEscapedHtml = RegExp(reEscapedHtml.source);
function unescape(string) {
  string = toString_default(string);
  return string && reHasEscapedHtml.test(string) ? string.replace(reEscapedHtml, unescapeHtmlChar_default) : string;
}
var unescape_default = unescape;

// node_modules/lodash-es/_createSet.js
var INFINITY6 = 1 / 0;
var createSet = !(Set_default && 1 / setToArray_default(new Set_default([, -0]))[1] == INFINITY6) ? noop_default : function(values2) {
  return new Set_default(values2);
};
var createSet_default = createSet;

// node_modules/lodash-es/_baseUniq.js
var LARGE_ARRAY_SIZE3 = 200;
function baseUniq(array, iteratee2, comparator) {
  var index = -1, includes2 = arrayIncludes_default, length = array.length, isCommon = true, result2 = [], seen = result2;
  if (comparator) {
    isCommon = false;
    includes2 = arrayIncludesWith_default;
  } else if (length >= LARGE_ARRAY_SIZE3) {
    var set2 = iteratee2 ? null : createSet_default(array);
    if (set2) {
      return setToArray_default(set2);
    }
    isCommon = false;
    includes2 = cacheHas_default;
    seen = new SetCache_default();
  } else {
    seen = iteratee2 ? [] : result2;
  }
  outer: while (++index < length) {
    var value = array[index], computed = iteratee2 ? iteratee2(value) : value;
    value = comparator || value !== 0 ? value : 0;
    if (isCommon && computed === computed) {
      var seenIndex = seen.length;
      while (seenIndex--) {
        if (seen[seenIndex] === computed) {
          continue outer;
        }
      }
      if (iteratee2) {
        seen.push(computed);
      }
      result2.push(value);
    } else if (!includes2(seen, computed, comparator)) {
      if (seen !== result2) {
        seen.push(computed);
      }
      result2.push(value);
    }
  }
  return result2;
}
var baseUniq_default = baseUniq;

// node_modules/lodash-es/union.js
var union = baseRest_default(function(arrays) {
  return baseUniq_default(baseFlatten_default(arrays, 1, isArrayLikeObject_default, true));
});
var union_default = union;

// node_modules/lodash-es/unionBy.js
var unionBy = baseRest_default(function(arrays) {
  var iteratee2 = last_default(arrays);
  if (isArrayLikeObject_default(iteratee2)) {
    iteratee2 = void 0;
  }
  return baseUniq_default(baseFlatten_default(arrays, 1, isArrayLikeObject_default, true), baseIteratee_default(iteratee2, 2));
});
var unionBy_default = unionBy;

// node_modules/lodash-es/unionWith.js
var unionWith = baseRest_default(function(arrays) {
  var comparator = last_default(arrays);
  comparator = typeof comparator == "function" ? comparator : void 0;
  return baseUniq_default(baseFlatten_default(arrays, 1, isArrayLikeObject_default, true), void 0, comparator);
});
var unionWith_default = unionWith;

// node_modules/lodash-es/uniq.js
function uniq(array) {
  return array && array.length ? baseUniq_default(array) : [];
}
var uniq_default = uniq;

// node_modules/lodash-es/uniqBy.js
function uniqBy(array, iteratee2) {
  return array && array.length ? baseUniq_default(array, baseIteratee_default(iteratee2, 2)) : [];
}
var uniqBy_default = uniqBy;

// node_modules/lodash-es/uniqWith.js
function uniqWith(array, comparator) {
  comparator = typeof comparator == "function" ? comparator : void 0;
  return array && array.length ? baseUniq_default(array, void 0, comparator) : [];
}
var uniqWith_default = uniqWith;

// node_modules/lodash-es/uniqueId.js
var idCounter = 0;
function uniqueId(prefix) {
  var id = ++idCounter;
  return toString_default(prefix) + id;
}
var uniqueId_default = uniqueId;

// node_modules/lodash-es/unset.js
function unset(object, path) {
  return object == null ? true : baseUnset_default(object, path);
}
var unset_default = unset;

// node_modules/lodash-es/unzip.js
var nativeMax15 = Math.max;
function unzip(array) {
  if (!(array && array.length)) {
    return [];
  }
  var length = 0;
  array = arrayFilter_default(array, function(group) {
    if (isArrayLikeObject_default(group)) {
      length = nativeMax15(group.length, length);
      return true;
    }
  });
  return baseTimes_default(length, function(index) {
    return arrayMap_default(array, baseProperty_default(index));
  });
}
var unzip_default = unzip;

// node_modules/lodash-es/unzipWith.js
function unzipWith(array, iteratee2) {
  if (!(array && array.length)) {
    return [];
  }
  var result2 = unzip_default(array);
  if (iteratee2 == null) {
    return result2;
  }
  return arrayMap_default(result2, function(group) {
    return apply_default(iteratee2, void 0, group);
  });
}
var unzipWith_default = unzipWith;

// node_modules/lodash-es/_baseUpdate.js
function baseUpdate(object, path, updater, customizer) {
  return baseSet_default(object, path, updater(baseGet_default(object, path)), customizer);
}
var baseUpdate_default = baseUpdate;

// node_modules/lodash-es/update.js
function update(object, path, updater) {
  return object == null ? object : baseUpdate_default(object, path, castFunction_default(updater));
}
var update_default = update;

// node_modules/lodash-es/updateWith.js
function updateWith(object, path, updater, customizer) {
  customizer = typeof customizer == "function" ? customizer : void 0;
  return object == null ? object : baseUpdate_default(object, path, castFunction_default(updater), customizer);
}
var updateWith_default = updateWith;

// node_modules/lodash-es/upperCase.js
var upperCase = createCompounder_default(function(result2, word, index) {
  return result2 + (index ? " " : "") + word.toUpperCase();
});
var upperCase_default = upperCase;

// node_modules/lodash-es/valuesIn.js
function valuesIn(object) {
  return object == null ? [] : baseValues_default(object, keysIn_default(object));
}
var valuesIn_default = valuesIn;

// node_modules/lodash-es/without.js
var without = baseRest_default(function(array, values2) {
  return isArrayLikeObject_default(array) ? baseDifference_default(array, values2) : [];
});
var without_default = without;

// node_modules/lodash-es/wrap.js
function wrap(value, wrapper) {
  return partial_default(castFunction_default(wrapper), value);
}
var wrap_default = wrap;

// node_modules/lodash-es/wrapperAt.js
var wrapperAt = flatRest_default(function(paths) {
  var length = paths.length, start = length ? paths[0] : 0, value = this.__wrapped__, interceptor = function(object) {
    return baseAt_default(object, paths);
  };
  if (length > 1 || this.__actions__.length || !(value instanceof LazyWrapper_default) || !isIndex_default(start)) {
    return this.thru(interceptor);
  }
  value = value.slice(start, +start + (length ? 1 : 0));
  value.__actions__.push({
    "func": thru_default,
    "args": [interceptor],
    "thisArg": void 0
  });
  return new LodashWrapper_default(value, this.__chain__).thru(function(array) {
    if (length && !array.length) {
      array.push(void 0);
    }
    return array;
  });
});
var wrapperAt_default = wrapperAt;

// node_modules/lodash-es/wrapperChain.js
function wrapperChain() {
  return chain_default(this);
}
var wrapperChain_default = wrapperChain;

// node_modules/lodash-es/wrapperReverse.js
function wrapperReverse() {
  var value = this.__wrapped__;
  if (value instanceof LazyWrapper_default) {
    var wrapped = value;
    if (this.__actions__.length) {
      wrapped = new LazyWrapper_default(this);
    }
    wrapped = wrapped.reverse();
    wrapped.__actions__.push({
      "func": thru_default,
      "args": [reverse_default],
      "thisArg": void 0
    });
    return new LodashWrapper_default(wrapped, this.__chain__);
  }
  return this.thru(reverse_default);
}
var wrapperReverse_default = wrapperReverse;

// node_modules/lodash-es/_baseXor.js
function baseXor(arrays, iteratee2, comparator) {
  var length = arrays.length;
  if (length < 2) {
    return length ? baseUniq_default(arrays[0]) : [];
  }
  var index = -1, result2 = Array(length);
  while (++index < length) {
    var array = arrays[index], othIndex = -1;
    while (++othIndex < length) {
      if (othIndex != index) {
        result2[index] = baseDifference_default(result2[index] || array, arrays[othIndex], iteratee2, comparator);
      }
    }
  }
  return baseUniq_default(baseFlatten_default(result2, 1), iteratee2, comparator);
}
var baseXor_default = baseXor;

// node_modules/lodash-es/xor.js
var xor = baseRest_default(function(arrays) {
  return baseXor_default(arrayFilter_default(arrays, isArrayLikeObject_default));
});
var xor_default = xor;

// node_modules/lodash-es/xorBy.js
var xorBy = baseRest_default(function(arrays) {
  var iteratee2 = last_default(arrays);
  if (isArrayLikeObject_default(iteratee2)) {
    iteratee2 = void 0;
  }
  return baseXor_default(arrayFilter_default(arrays, isArrayLikeObject_default), baseIteratee_default(iteratee2, 2));
});
var xorBy_default = xorBy;

// node_modules/lodash-es/xorWith.js
var xorWith = baseRest_default(function(arrays) {
  var comparator = last_default(arrays);
  comparator = typeof comparator == "function" ? comparator : void 0;
  return baseXor_default(arrayFilter_default(arrays, isArrayLikeObject_default), void 0, comparator);
});
var xorWith_default = xorWith;

// node_modules/lodash-es/zip.js
var zip = baseRest_default(unzip_default);
var zip_default = zip;

// node_modules/lodash-es/_baseZipObject.js
function baseZipObject(props, values2, assignFunc) {
  var index = -1, length = props.length, valsLength = values2.length, result2 = {};
  while (++index < length) {
    var value = index < valsLength ? values2[index] : void 0;
    assignFunc(result2, props[index], value);
  }
  return result2;
}
var baseZipObject_default = baseZipObject;

// node_modules/lodash-es/zipObject.js
function zipObject(props, values2) {
  return baseZipObject_default(props || [], values2 || [], assignValue_default);
}
var zipObject_default = zipObject;

// node_modules/lodash-es/zipObjectDeep.js
function zipObjectDeep(props, values2) {
  return baseZipObject_default(props || [], values2 || [], baseSet_default);
}
var zipObjectDeep_default = zipObjectDeep;

// node_modules/lodash-es/zipWith.js
var zipWith = baseRest_default(function(arrays) {
  var length = arrays.length, iteratee2 = length > 1 ? arrays[length - 1] : void 0;
  iteratee2 = typeof iteratee2 == "function" ? (arrays.pop(), iteratee2) : void 0;
  return unzipWith_default(arrays, iteratee2);
});
var zipWith_default = zipWith;

// node_modules/lodash-es/array.default.js
var array_default_default = {
  chunk: chunk_default,
  compact: compact_default,
  concat: concat_default,
  difference: difference_default,
  differenceBy: differenceBy_default,
  differenceWith: differenceWith_default,
  drop: drop_default,
  dropRight: dropRight_default,
  dropRightWhile: dropRightWhile_default,
  dropWhile: dropWhile_default,
  fill: fill_default,
  findIndex: findIndex_default,
  findLastIndex: findLastIndex_default,
  first: head_default,
  flatten: flatten_default,
  flattenDeep: flattenDeep_default,
  flattenDepth: flattenDepth_default,
  fromPairs: fromPairs_default,
  head: head_default,
  indexOf: indexOf_default,
  initial: initial_default,
  intersection: intersection_default,
  intersectionBy: intersectionBy_default,
  intersectionWith: intersectionWith_default,
  join: join_default,
  last: last_default,
  lastIndexOf: lastIndexOf_default,
  nth: nth_default,
  pull: pull_default,
  pullAll: pullAll_default,
  pullAllBy: pullAllBy_default,
  pullAllWith: pullAllWith_default,
  pullAt: pullAt_default,
  remove: remove_default,
  reverse: reverse_default,
  slice: slice_default,
  sortedIndex: sortedIndex_default,
  sortedIndexBy: sortedIndexBy_default,
  sortedIndexOf: sortedIndexOf_default,
  sortedLastIndex: sortedLastIndex_default,
  sortedLastIndexBy: sortedLastIndexBy_default,
  sortedLastIndexOf: sortedLastIndexOf_default,
  sortedUniq: sortedUniq_default,
  sortedUniqBy: sortedUniqBy_default,
  tail: tail_default,
  take: take_default,
  takeRight: takeRight_default,
  takeRightWhile: takeRightWhile_default,
  takeWhile: takeWhile_default,
  union: union_default,
  unionBy: unionBy_default,
  unionWith: unionWith_default,
  uniq: uniq_default,
  uniqBy: uniqBy_default,
  uniqWith: uniqWith_default,
  unzip: unzip_default,
  unzipWith: unzipWith_default,
  without: without_default,
  xor: xor_default,
  xorBy: xorBy_default,
  xorWith: xorWith_default,
  zip: zip_default,
  zipObject: zipObject_default,
  zipObjectDeep: zipObjectDeep_default,
  zipWith: zipWith_default
};

// node_modules/lodash-es/collection.default.js
var collection_default_default = {
  countBy: countBy_default,
  each: forEach_default,
  eachRight: forEachRight_default,
  every: every_default,
  filter: filter_default,
  find: find_default,
  findLast: findLast_default,
  flatMap: flatMap_default,
  flatMapDeep: flatMapDeep_default,
  flatMapDepth: flatMapDepth_default,
  forEach: forEach_default,
  forEachRight: forEachRight_default,
  groupBy: groupBy_default,
  includes: includes_default,
  invokeMap: invokeMap_default,
  keyBy: keyBy_default,
  map: map_default,
  orderBy: orderBy_default,
  partition: partition_default,
  reduce: reduce_default,
  reduceRight: reduceRight_default,
  reject: reject_default,
  sample: sample_default,
  sampleSize: sampleSize_default,
  shuffle: shuffle_default,
  size: size_default,
  some: some_default,
  sortBy: sortBy_default
};

// node_modules/lodash-es/date.default.js
var date_default_default = {
  now: now_default
};

// node_modules/lodash-es/function.default.js
var function_default_default = {
  after: after_default,
  ary: ary_default,
  before: before_default,
  bind: bind_default,
  bindKey: bindKey_default,
  curry: curry_default,
  curryRight: curryRight_default,
  debounce: debounce_default,
  defer: defer_default,
  delay: delay_default,
  flip: flip_default,
  memoize: memoize_default,
  negate: negate_default,
  once: once_default,
  overArgs: overArgs_default,
  partial: partial_default,
  partialRight: partialRight_default,
  rearg: rearg_default,
  rest: rest_default,
  spread: spread_default,
  throttle: throttle_default,
  unary: unary_default,
  wrap: wrap_default
};

// node_modules/lodash-es/lang.default.js
var lang_default_default = {
  castArray: castArray_default,
  clone: clone_default,
  cloneDeep: cloneDeep_default,
  cloneDeepWith: cloneDeepWith_default,
  cloneWith: cloneWith_default,
  conformsTo: conformsTo_default,
  eq: eq_default,
  gt: gt_default,
  gte: gte_default,
  isArguments: isArguments_default,
  isArray: isArray_default,
  isArrayBuffer: isArrayBuffer_default,
  isArrayLike: isArrayLike_default,
  isArrayLikeObject: isArrayLikeObject_default,
  isBoolean: isBoolean_default,
  isBuffer: isBuffer_default,
  isDate: isDate_default,
  isElement: isElement_default,
  isEmpty: isEmpty_default,
  isEqual: isEqual_default,
  isEqualWith: isEqualWith_default,
  isError: isError_default,
  isFinite: isFinite_default,
  isFunction: isFunction_default,
  isInteger: isInteger_default,
  isLength: isLength_default,
  isMap: isMap_default,
  isMatch: isMatch_default,
  isMatchWith: isMatchWith_default,
  isNaN: isNaN_default,
  isNative: isNative_default,
  isNil: isNil_default,
  isNull: isNull_default,
  isNumber: isNumber_default,
  isObject: isObject_default,
  isObjectLike: isObjectLike_default,
  isPlainObject: isPlainObject_default,
  isRegExp: isRegExp_default,
  isSafeInteger: isSafeInteger_default,
  isSet: isSet_default,
  isString: isString_default,
  isSymbol: isSymbol_default,
  isTypedArray: isTypedArray_default,
  isUndefined: isUndefined_default,
  isWeakMap: isWeakMap_default,
  isWeakSet: isWeakSet_default,
  lt: lt_default,
  lte: lte_default,
  toArray: toArray_default,
  toFinite: toFinite_default,
  toInteger: toInteger_default,
  toLength: toLength_default,
  toNumber: toNumber_default,
  toPlainObject: toPlainObject_default,
  toSafeInteger: toSafeInteger_default,
  toString: toString_default
};

// node_modules/lodash-es/math.default.js
var math_default_default = {
  add: add_default,
  ceil: ceil_default,
  divide: divide_default,
  floor: floor_default,
  max: max_default,
  maxBy: maxBy_default,
  mean: mean_default,
  meanBy: meanBy_default,
  min: min_default,
  minBy: minBy_default,
  multiply: multiply_default,
  round: round_default,
  subtract: subtract_default,
  sum: sum_default,
  sumBy: sumBy_default
};

// node_modules/lodash-es/number.default.js
var number_default_default = {
  clamp: clamp_default,
  inRange: inRange_default,
  random: random_default
};

// node_modules/lodash-es/object.default.js
var object_default_default = {
  assign: assign_default,
  assignIn: assignIn_default,
  assignInWith: assignInWith_default,
  assignWith: assignWith_default,
  at: at_default,
  create: create_default,
  defaults: defaults_default,
  defaultsDeep: defaultsDeep_default,
  entries: toPairs_default,
  entriesIn: toPairsIn_default,
  extend: assignIn_default,
  extendWith: assignInWith_default,
  findKey: findKey_default,
  findLastKey: findLastKey_default,
  forIn: forIn_default,
  forInRight: forInRight_default,
  forOwn: forOwn_default,
  forOwnRight: forOwnRight_default,
  functions: functions_default,
  functionsIn: functionsIn_default,
  get: get_default,
  has: has_default,
  hasIn: hasIn_default,
  invert: invert_default,
  invertBy: invertBy_default,
  invoke: invoke_default,
  keys: keys_default,
  keysIn: keysIn_default,
  mapKeys: mapKeys_default,
  mapValues: mapValues_default,
  merge: merge_default,
  mergeWith: mergeWith_default,
  omit: omit_default,
  omitBy: omitBy_default,
  pick: pick_default,
  pickBy: pickBy_default,
  result: result_default,
  set: set_default,
  setWith: setWith_default,
  toPairs: toPairs_default,
  toPairsIn: toPairsIn_default,
  transform: transform_default,
  unset: unset_default,
  update: update_default,
  updateWith: updateWith_default,
  values: values_default,
  valuesIn: valuesIn_default
};

// node_modules/lodash-es/seq.default.js
var seq_default_default = {
  at: wrapperAt_default,
  chain: chain_default,
  commit: commit_default,
  lodash: wrapperLodash_default,
  next: next_default,
  plant: plant_default,
  reverse: wrapperReverse_default,
  tap: tap_default,
  thru: thru_default,
  toIterator: toIterator_default,
  toJSON: wrapperValue_default,
  value: wrapperValue_default,
  valueOf: wrapperValue_default,
  wrapperChain: wrapperChain_default
};

// node_modules/lodash-es/string.default.js
var string_default_default = {
  camelCase: camelCase_default,
  capitalize: capitalize_default,
  deburr: deburr_default,
  endsWith: endsWith_default,
  escape: escape_default,
  escapeRegExp: escapeRegExp_default,
  kebabCase: kebabCase_default,
  lowerCase: lowerCase_default,
  lowerFirst: lowerFirst_default,
  pad: pad_default,
  padEnd: padEnd_default,
  padStart: padStart_default,
  parseInt: parseInt_default,
  repeat: repeat_default,
  replace: replace_default,
  snakeCase: snakeCase_default,
  split: split_default,
  startCase: startCase_default,
  startsWith: startsWith_default,
  template: template_default,
  templateSettings: templateSettings_default,
  toLower: toLower_default,
  toUpper: toUpper_default,
  trim: trim_default,
  trimEnd: trimEnd_default,
  trimStart: trimStart_default,
  truncate: truncate_default,
  unescape: unescape_default,
  upperCase: upperCase_default,
  upperFirst: upperFirst_default,
  words: words_default
};

// node_modules/lodash-es/util.default.js
var util_default_default = {
  attempt: attempt_default,
  bindAll: bindAll_default,
  cond: cond_default,
  conforms: conforms_default,
  constant: constant_default,
  defaultTo: defaultTo_default,
  flow: flow_default,
  flowRight: flowRight_default,
  identity: identity_default,
  iteratee: iteratee_default,
  matches: matches_default,
  matchesProperty: matchesProperty_default,
  method: method_default,
  methodOf: methodOf_default,
  mixin: mixin_default,
  noop: noop_default,
  nthArg: nthArg_default,
  over: over_default,
  overEvery: overEvery_default,
  overSome: overSome_default,
  property: property_default,
  propertyOf: propertyOf_default,
  range: range_default,
  rangeRight: rangeRight_default,
  stubArray: stubArray_default,
  stubFalse: stubFalse_default,
  stubObject: stubObject_default,
  stubString: stubString_default,
  stubTrue: stubTrue_default,
  times: times_default,
  toPath: toPath_default,
  uniqueId: uniqueId_default
};

// node_modules/lodash-es/_lazyClone.js
function lazyClone() {
  var result2 = new LazyWrapper_default(this.__wrapped__);
  result2.__actions__ = copyArray_default(this.__actions__);
  result2.__dir__ = this.__dir__;
  result2.__filtered__ = this.__filtered__;
  result2.__iteratees__ = copyArray_default(this.__iteratees__);
  result2.__takeCount__ = this.__takeCount__;
  result2.__views__ = copyArray_default(this.__views__);
  return result2;
}
var lazyClone_default = lazyClone;

// node_modules/lodash-es/_lazyReverse.js
function lazyReverse() {
  if (this.__filtered__) {
    var result2 = new LazyWrapper_default(this);
    result2.__dir__ = -1;
    result2.__filtered__ = true;
  } else {
    result2 = this.clone();
    result2.__dir__ *= -1;
  }
  return result2;
}
var lazyReverse_default = lazyReverse;

// node_modules/lodash-es/_getView.js
var nativeMax16 = Math.max;
var nativeMin13 = Math.min;
function getView(start, end, transforms) {
  var index = -1, length = transforms.length;
  while (++index < length) {
    var data = transforms[index], size2 = data.size;
    switch (data.type) {
      case "drop":
        start += size2;
        break;
      case "dropRight":
        end -= size2;
        break;
      case "take":
        end = nativeMin13(end, start + size2);
        break;
      case "takeRight":
        start = nativeMax16(start, end - size2);
        break;
    }
  }
  return {
    "start": start,
    "end": end
  };
}
var getView_default = getView;

// node_modules/lodash-es/_lazyValue.js
var LAZY_FILTER_FLAG = 1;
var LAZY_MAP_FLAG = 2;
var nativeMin14 = Math.min;
function lazyValue() {
  var array = this.__wrapped__.value(), dir = this.__dir__, isArr = isArray_default(array), isRight = dir < 0, arrLength = isArr ? array.length : 0, view = getView_default(0, arrLength, this.__views__), start = view.start, end = view.end, length = end - start, index = isRight ? end : start - 1, iteratees = this.__iteratees__, iterLength = iteratees.length, resIndex = 0, takeCount = nativeMin14(length, this.__takeCount__);
  if (!isArr || !isRight && arrLength == length && takeCount == length) {
    return baseWrapperValue_default(array, this.__actions__);
  }
  var result2 = [];
  outer: while (length-- && resIndex < takeCount) {
    index += dir;
    var iterIndex = -1, value = array[index];
    while (++iterIndex < iterLength) {
      var data = iteratees[iterIndex], iteratee2 = data.iteratee, type = data.type, computed = iteratee2(value);
      if (type == LAZY_MAP_FLAG) {
        value = computed;
      } else if (!computed) {
        if (type == LAZY_FILTER_FLAG) {
          continue outer;
        } else {
          break outer;
        }
      }
    }
    result2[resIndex++] = value;
  }
  return result2;
}
var lazyValue_default = lazyValue;

// node_modules/lodash-es/lodash.default.js
var VERSION = "4.17.21";
var WRAP_BIND_KEY_FLAG7 = 2;
var LAZY_FILTER_FLAG2 = 1;
var LAZY_WHILE_FLAG = 3;
var MAX_ARRAY_LENGTH7 = 4294967295;
var arrayProto6 = Array.prototype;
var objectProto29 = Object.prototype;
var hasOwnProperty25 = objectProto29.hasOwnProperty;
var symIterator2 = Symbol_default ? Symbol_default.iterator : void 0;
var nativeMax17 = Math.max;
var nativeMin15 = Math.min;
var mixin2 = /* @__PURE__ */ function(func) {
  return function(object, source, options) {
    if (options == null) {
      var isObj = isObject_default(source), props = isObj && keys_default(source), methodNames = props && props.length && baseFunctions_default(source, props);
      if (!(methodNames ? methodNames.length : isObj)) {
        options = source;
        source = object;
        object = this;
      }
    }
    return func(object, source, options);
  };
}(mixin_default);
wrapperLodash_default.after = function_default_default.after;
wrapperLodash_default.ary = function_default_default.ary;
wrapperLodash_default.assign = object_default_default.assign;
wrapperLodash_default.assignIn = object_default_default.assignIn;
wrapperLodash_default.assignInWith = object_default_default.assignInWith;
wrapperLodash_default.assignWith = object_default_default.assignWith;
wrapperLodash_default.at = object_default_default.at;
wrapperLodash_default.before = function_default_default.before;
wrapperLodash_default.bind = function_default_default.bind;
wrapperLodash_default.bindAll = util_default_default.bindAll;
wrapperLodash_default.bindKey = function_default_default.bindKey;
wrapperLodash_default.castArray = lang_default_default.castArray;
wrapperLodash_default.chain = seq_default_default.chain;
wrapperLodash_default.chunk = array_default_default.chunk;
wrapperLodash_default.compact = array_default_default.compact;
wrapperLodash_default.concat = array_default_default.concat;
wrapperLodash_default.cond = util_default_default.cond;
wrapperLodash_default.conforms = util_default_default.conforms;
wrapperLodash_default.constant = util_default_default.constant;
wrapperLodash_default.countBy = collection_default_default.countBy;
wrapperLodash_default.create = object_default_default.create;
wrapperLodash_default.curry = function_default_default.curry;
wrapperLodash_default.curryRight = function_default_default.curryRight;
wrapperLodash_default.debounce = function_default_default.debounce;
wrapperLodash_default.defaults = object_default_default.defaults;
wrapperLodash_default.defaultsDeep = object_default_default.defaultsDeep;
wrapperLodash_default.defer = function_default_default.defer;
wrapperLodash_default.delay = function_default_default.delay;
wrapperLodash_default.difference = array_default_default.difference;
wrapperLodash_default.differenceBy = array_default_default.differenceBy;
wrapperLodash_default.differenceWith = array_default_default.differenceWith;
wrapperLodash_default.drop = array_default_default.drop;
wrapperLodash_default.dropRight = array_default_default.dropRight;
wrapperLodash_default.dropRightWhile = array_default_default.dropRightWhile;
wrapperLodash_default.dropWhile = array_default_default.dropWhile;
wrapperLodash_default.fill = array_default_default.fill;
wrapperLodash_default.filter = collection_default_default.filter;
wrapperLodash_default.flatMap = collection_default_default.flatMap;
wrapperLodash_default.flatMapDeep = collection_default_default.flatMapDeep;
wrapperLodash_default.flatMapDepth = collection_default_default.flatMapDepth;
wrapperLodash_default.flatten = array_default_default.flatten;
wrapperLodash_default.flattenDeep = array_default_default.flattenDeep;
wrapperLodash_default.flattenDepth = array_default_default.flattenDepth;
wrapperLodash_default.flip = function_default_default.flip;
wrapperLodash_default.flow = util_default_default.flow;
wrapperLodash_default.flowRight = util_default_default.flowRight;
wrapperLodash_default.fromPairs = array_default_default.fromPairs;
wrapperLodash_default.functions = object_default_default.functions;
wrapperLodash_default.functionsIn = object_default_default.functionsIn;
wrapperLodash_default.groupBy = collection_default_default.groupBy;
wrapperLodash_default.initial = array_default_default.initial;
wrapperLodash_default.intersection = array_default_default.intersection;
wrapperLodash_default.intersectionBy = array_default_default.intersectionBy;
wrapperLodash_default.intersectionWith = array_default_default.intersectionWith;
wrapperLodash_default.invert = object_default_default.invert;
wrapperLodash_default.invertBy = object_default_default.invertBy;
wrapperLodash_default.invokeMap = collection_default_default.invokeMap;
wrapperLodash_default.iteratee = util_default_default.iteratee;
wrapperLodash_default.keyBy = collection_default_default.keyBy;
wrapperLodash_default.keys = keys_default;
wrapperLodash_default.keysIn = object_default_default.keysIn;
wrapperLodash_default.map = collection_default_default.map;
wrapperLodash_default.mapKeys = object_default_default.mapKeys;
wrapperLodash_default.mapValues = object_default_default.mapValues;
wrapperLodash_default.matches = util_default_default.matches;
wrapperLodash_default.matchesProperty = util_default_default.matchesProperty;
wrapperLodash_default.memoize = function_default_default.memoize;
wrapperLodash_default.merge = object_default_default.merge;
wrapperLodash_default.mergeWith = object_default_default.mergeWith;
wrapperLodash_default.method = util_default_default.method;
wrapperLodash_default.methodOf = util_default_default.methodOf;
wrapperLodash_default.mixin = mixin2;
wrapperLodash_default.negate = negate_default;
wrapperLodash_default.nthArg = util_default_default.nthArg;
wrapperLodash_default.omit = object_default_default.omit;
wrapperLodash_default.omitBy = object_default_default.omitBy;
wrapperLodash_default.once = function_default_default.once;
wrapperLodash_default.orderBy = collection_default_default.orderBy;
wrapperLodash_default.over = util_default_default.over;
wrapperLodash_default.overArgs = function_default_default.overArgs;
wrapperLodash_default.overEvery = util_default_default.overEvery;
wrapperLodash_default.overSome = util_default_default.overSome;
wrapperLodash_default.partial = function_default_default.partial;
wrapperLodash_default.partialRight = function_default_default.partialRight;
wrapperLodash_default.partition = collection_default_default.partition;
wrapperLodash_default.pick = object_default_default.pick;
wrapperLodash_default.pickBy = object_default_default.pickBy;
wrapperLodash_default.property = util_default_default.property;
wrapperLodash_default.propertyOf = util_default_default.propertyOf;
wrapperLodash_default.pull = array_default_default.pull;
wrapperLodash_default.pullAll = array_default_default.pullAll;
wrapperLodash_default.pullAllBy = array_default_default.pullAllBy;
wrapperLodash_default.pullAllWith = array_default_default.pullAllWith;
wrapperLodash_default.pullAt = array_default_default.pullAt;
wrapperLodash_default.range = util_default_default.range;
wrapperLodash_default.rangeRight = util_default_default.rangeRight;
wrapperLodash_default.rearg = function_default_default.rearg;
wrapperLodash_default.reject = collection_default_default.reject;
wrapperLodash_default.remove = array_default_default.remove;
wrapperLodash_default.rest = function_default_default.rest;
wrapperLodash_default.reverse = array_default_default.reverse;
wrapperLodash_default.sampleSize = collection_default_default.sampleSize;
wrapperLodash_default.set = object_default_default.set;
wrapperLodash_default.setWith = object_default_default.setWith;
wrapperLodash_default.shuffle = collection_default_default.shuffle;
wrapperLodash_default.slice = array_default_default.slice;
wrapperLodash_default.sortBy = collection_default_default.sortBy;
wrapperLodash_default.sortedUniq = array_default_default.sortedUniq;
wrapperLodash_default.sortedUniqBy = array_default_default.sortedUniqBy;
wrapperLodash_default.split = string_default_default.split;
wrapperLodash_default.spread = function_default_default.spread;
wrapperLodash_default.tail = array_default_default.tail;
wrapperLodash_default.take = array_default_default.take;
wrapperLodash_default.takeRight = array_default_default.takeRight;
wrapperLodash_default.takeRightWhile = array_default_default.takeRightWhile;
wrapperLodash_default.takeWhile = array_default_default.takeWhile;
wrapperLodash_default.tap = seq_default_default.tap;
wrapperLodash_default.throttle = function_default_default.throttle;
wrapperLodash_default.thru = thru_default;
wrapperLodash_default.toArray = lang_default_default.toArray;
wrapperLodash_default.toPairs = object_default_default.toPairs;
wrapperLodash_default.toPairsIn = object_default_default.toPairsIn;
wrapperLodash_default.toPath = util_default_default.toPath;
wrapperLodash_default.toPlainObject = lang_default_default.toPlainObject;
wrapperLodash_default.transform = object_default_default.transform;
wrapperLodash_default.unary = function_default_default.unary;
wrapperLodash_default.union = array_default_default.union;
wrapperLodash_default.unionBy = array_default_default.unionBy;
wrapperLodash_default.unionWith = array_default_default.unionWith;
wrapperLodash_default.uniq = array_default_default.uniq;
wrapperLodash_default.uniqBy = array_default_default.uniqBy;
wrapperLodash_default.uniqWith = array_default_default.uniqWith;
wrapperLodash_default.unset = object_default_default.unset;
wrapperLodash_default.unzip = array_default_default.unzip;
wrapperLodash_default.unzipWith = array_default_default.unzipWith;
wrapperLodash_default.update = object_default_default.update;
wrapperLodash_default.updateWith = object_default_default.updateWith;
wrapperLodash_default.values = object_default_default.values;
wrapperLodash_default.valuesIn = object_default_default.valuesIn;
wrapperLodash_default.without = array_default_default.without;
wrapperLodash_default.words = string_default_default.words;
wrapperLodash_default.wrap = function_default_default.wrap;
wrapperLodash_default.xor = array_default_default.xor;
wrapperLodash_default.xorBy = array_default_default.xorBy;
wrapperLodash_default.xorWith = array_default_default.xorWith;
wrapperLodash_default.zip = array_default_default.zip;
wrapperLodash_default.zipObject = array_default_default.zipObject;
wrapperLodash_default.zipObjectDeep = array_default_default.zipObjectDeep;
wrapperLodash_default.zipWith = array_default_default.zipWith;
wrapperLodash_default.entries = object_default_default.toPairs;
wrapperLodash_default.entriesIn = object_default_default.toPairsIn;
wrapperLodash_default.extend = object_default_default.assignIn;
wrapperLodash_default.extendWith = object_default_default.assignInWith;
mixin2(wrapperLodash_default, wrapperLodash_default);
wrapperLodash_default.add = math_default_default.add;
wrapperLodash_default.attempt = util_default_default.attempt;
wrapperLodash_default.camelCase = string_default_default.camelCase;
wrapperLodash_default.capitalize = string_default_default.capitalize;
wrapperLodash_default.ceil = math_default_default.ceil;
wrapperLodash_default.clamp = number_default_default.clamp;
wrapperLodash_default.clone = lang_default_default.clone;
wrapperLodash_default.cloneDeep = lang_default_default.cloneDeep;
wrapperLodash_default.cloneDeepWith = lang_default_default.cloneDeepWith;
wrapperLodash_default.cloneWith = lang_default_default.cloneWith;
wrapperLodash_default.conformsTo = lang_default_default.conformsTo;
wrapperLodash_default.deburr = string_default_default.deburr;
wrapperLodash_default.defaultTo = util_default_default.defaultTo;
wrapperLodash_default.divide = math_default_default.divide;
wrapperLodash_default.endsWith = string_default_default.endsWith;
wrapperLodash_default.eq = lang_default_default.eq;
wrapperLodash_default.escape = string_default_default.escape;
wrapperLodash_default.escapeRegExp = string_default_default.escapeRegExp;
wrapperLodash_default.every = collection_default_default.every;
wrapperLodash_default.find = collection_default_default.find;
wrapperLodash_default.findIndex = array_default_default.findIndex;
wrapperLodash_default.findKey = object_default_default.findKey;
wrapperLodash_default.findLast = collection_default_default.findLast;
wrapperLodash_default.findLastIndex = array_default_default.findLastIndex;
wrapperLodash_default.findLastKey = object_default_default.findLastKey;
wrapperLodash_default.floor = math_default_default.floor;
wrapperLodash_default.forEach = collection_default_default.forEach;
wrapperLodash_default.forEachRight = collection_default_default.forEachRight;
wrapperLodash_default.forIn = object_default_default.forIn;
wrapperLodash_default.forInRight = object_default_default.forInRight;
wrapperLodash_default.forOwn = object_default_default.forOwn;
wrapperLodash_default.forOwnRight = object_default_default.forOwnRight;
wrapperLodash_default.get = object_default_default.get;
wrapperLodash_default.gt = lang_default_default.gt;
wrapperLodash_default.gte = lang_default_default.gte;
wrapperLodash_default.has = object_default_default.has;
wrapperLodash_default.hasIn = object_default_default.hasIn;
wrapperLodash_default.head = array_default_default.head;
wrapperLodash_default.identity = identity_default;
wrapperLodash_default.includes = collection_default_default.includes;
wrapperLodash_default.indexOf = array_default_default.indexOf;
wrapperLodash_default.inRange = number_default_default.inRange;
wrapperLodash_default.invoke = object_default_default.invoke;
wrapperLodash_default.isArguments = lang_default_default.isArguments;
wrapperLodash_default.isArray = isArray_default;
wrapperLodash_default.isArrayBuffer = lang_default_default.isArrayBuffer;
wrapperLodash_default.isArrayLike = lang_default_default.isArrayLike;
wrapperLodash_default.isArrayLikeObject = lang_default_default.isArrayLikeObject;
wrapperLodash_default.isBoolean = lang_default_default.isBoolean;
wrapperLodash_default.isBuffer = lang_default_default.isBuffer;
wrapperLodash_default.isDate = lang_default_default.isDate;
wrapperLodash_default.isElement = lang_default_default.isElement;
wrapperLodash_default.isEmpty = lang_default_default.isEmpty;
wrapperLodash_default.isEqual = lang_default_default.isEqual;
wrapperLodash_default.isEqualWith = lang_default_default.isEqualWith;
wrapperLodash_default.isError = lang_default_default.isError;
wrapperLodash_default.isFinite = lang_default_default.isFinite;
wrapperLodash_default.isFunction = lang_default_default.isFunction;
wrapperLodash_default.isInteger = lang_default_default.isInteger;
wrapperLodash_default.isLength = lang_default_default.isLength;
wrapperLodash_default.isMap = lang_default_default.isMap;
wrapperLodash_default.isMatch = lang_default_default.isMatch;
wrapperLodash_default.isMatchWith = lang_default_default.isMatchWith;
wrapperLodash_default.isNaN = lang_default_default.isNaN;
wrapperLodash_default.isNative = lang_default_default.isNative;
wrapperLodash_default.isNil = lang_default_default.isNil;
wrapperLodash_default.isNull = lang_default_default.isNull;
wrapperLodash_default.isNumber = lang_default_default.isNumber;
wrapperLodash_default.isObject = isObject_default;
wrapperLodash_default.isObjectLike = lang_default_default.isObjectLike;
wrapperLodash_default.isPlainObject = lang_default_default.isPlainObject;
wrapperLodash_default.isRegExp = lang_default_default.isRegExp;
wrapperLodash_default.isSafeInteger = lang_default_default.isSafeInteger;
wrapperLodash_default.isSet = lang_default_default.isSet;
wrapperLodash_default.isString = lang_default_default.isString;
wrapperLodash_default.isSymbol = lang_default_default.isSymbol;
wrapperLodash_default.isTypedArray = lang_default_default.isTypedArray;
wrapperLodash_default.isUndefined = lang_default_default.isUndefined;
wrapperLodash_default.isWeakMap = lang_default_default.isWeakMap;
wrapperLodash_default.isWeakSet = lang_default_default.isWeakSet;
wrapperLodash_default.join = array_default_default.join;
wrapperLodash_default.kebabCase = string_default_default.kebabCase;
wrapperLodash_default.last = last_default;
wrapperLodash_default.lastIndexOf = array_default_default.lastIndexOf;
wrapperLodash_default.lowerCase = string_default_default.lowerCase;
wrapperLodash_default.lowerFirst = string_default_default.lowerFirst;
wrapperLodash_default.lt = lang_default_default.lt;
wrapperLodash_default.lte = lang_default_default.lte;
wrapperLodash_default.max = math_default_default.max;
wrapperLodash_default.maxBy = math_default_default.maxBy;
wrapperLodash_default.mean = math_default_default.mean;
wrapperLodash_default.meanBy = math_default_default.meanBy;
wrapperLodash_default.min = math_default_default.min;
wrapperLodash_default.minBy = math_default_default.minBy;
wrapperLodash_default.stubArray = util_default_default.stubArray;
wrapperLodash_default.stubFalse = util_default_default.stubFalse;
wrapperLodash_default.stubObject = util_default_default.stubObject;
wrapperLodash_default.stubString = util_default_default.stubString;
wrapperLodash_default.stubTrue = util_default_default.stubTrue;
wrapperLodash_default.multiply = math_default_default.multiply;
wrapperLodash_default.nth = array_default_default.nth;
wrapperLodash_default.noop = util_default_default.noop;
wrapperLodash_default.now = date_default_default.now;
wrapperLodash_default.pad = string_default_default.pad;
wrapperLodash_default.padEnd = string_default_default.padEnd;
wrapperLodash_default.padStart = string_default_default.padStart;
wrapperLodash_default.parseInt = string_default_default.parseInt;
wrapperLodash_default.random = number_default_default.random;
wrapperLodash_default.reduce = collection_default_default.reduce;
wrapperLodash_default.reduceRight = collection_default_default.reduceRight;
wrapperLodash_default.repeat = string_default_default.repeat;
wrapperLodash_default.replace = string_default_default.replace;
wrapperLodash_default.result = object_default_default.result;
wrapperLodash_default.round = math_default_default.round;
wrapperLodash_default.sample = collection_default_default.sample;
wrapperLodash_default.size = collection_default_default.size;
wrapperLodash_default.snakeCase = string_default_default.snakeCase;
wrapperLodash_default.some = collection_default_default.some;
wrapperLodash_default.sortedIndex = array_default_default.sortedIndex;
wrapperLodash_default.sortedIndexBy = array_default_default.sortedIndexBy;
wrapperLodash_default.sortedIndexOf = array_default_default.sortedIndexOf;
wrapperLodash_default.sortedLastIndex = array_default_default.sortedLastIndex;
wrapperLodash_default.sortedLastIndexBy = array_default_default.sortedLastIndexBy;
wrapperLodash_default.sortedLastIndexOf = array_default_default.sortedLastIndexOf;
wrapperLodash_default.startCase = string_default_default.startCase;
wrapperLodash_default.startsWith = string_default_default.startsWith;
wrapperLodash_default.subtract = math_default_default.subtract;
wrapperLodash_default.sum = math_default_default.sum;
wrapperLodash_default.sumBy = math_default_default.sumBy;
wrapperLodash_default.template = string_default_default.template;
wrapperLodash_default.times = util_default_default.times;
wrapperLodash_default.toFinite = lang_default_default.toFinite;
wrapperLodash_default.toInteger = toInteger_default;
wrapperLodash_default.toLength = lang_default_default.toLength;
wrapperLodash_default.toLower = string_default_default.toLower;
wrapperLodash_default.toNumber = lang_default_default.toNumber;
wrapperLodash_default.toSafeInteger = lang_default_default.toSafeInteger;
wrapperLodash_default.toString = lang_default_default.toString;
wrapperLodash_default.toUpper = string_default_default.toUpper;
wrapperLodash_default.trim = string_default_default.trim;
wrapperLodash_default.trimEnd = string_default_default.trimEnd;
wrapperLodash_default.trimStart = string_default_default.trimStart;
wrapperLodash_default.truncate = string_default_default.truncate;
wrapperLodash_default.unescape = string_default_default.unescape;
wrapperLodash_default.uniqueId = util_default_default.uniqueId;
wrapperLodash_default.upperCase = string_default_default.upperCase;
wrapperLodash_default.upperFirst = string_default_default.upperFirst;
wrapperLodash_default.each = collection_default_default.forEach;
wrapperLodash_default.eachRight = collection_default_default.forEachRight;
wrapperLodash_default.first = array_default_default.head;
mixin2(wrapperLodash_default, function() {
  var source = {};
  baseForOwn_default(wrapperLodash_default, function(func, methodName) {
    if (!hasOwnProperty25.call(wrapperLodash_default.prototype, methodName)) {
      source[methodName] = func;
    }
  });
  return source;
}(), {
  "chain": false
});
wrapperLodash_default.VERSION = VERSION;
(wrapperLodash_default.templateSettings = string_default_default.templateSettings).imports._ = wrapperLodash_default;
arrayEach_default(["bind", "bindKey", "curry", "curryRight", "partial", "partialRight"], function(methodName) {
  wrapperLodash_default[methodName].placeholder = wrapperLodash_default;
});
arrayEach_default(["drop", "take"], function(methodName, index) {
  LazyWrapper_default.prototype[methodName] = function(n) {
    n = n === void 0 ? 1 : nativeMax17(toInteger_default(n), 0);
    var result2 = this.__filtered__ && !index ? new LazyWrapper_default(this) : this.clone();
    if (result2.__filtered__) {
      result2.__takeCount__ = nativeMin15(n, result2.__takeCount__);
    } else {
      result2.__views__.push({
        "size": nativeMin15(n, MAX_ARRAY_LENGTH7),
        "type": methodName + (result2.__dir__ < 0 ? "Right" : "")
      });
    }
    return result2;
  };
  LazyWrapper_default.prototype[methodName + "Right"] = function(n) {
    return this.reverse()[methodName](n).reverse();
  };
});
arrayEach_default(["filter", "map", "takeWhile"], function(methodName, index) {
  var type = index + 1, isFilter = type == LAZY_FILTER_FLAG2 || type == LAZY_WHILE_FLAG;
  LazyWrapper_default.prototype[methodName] = function(iteratee2) {
    var result2 = this.clone();
    result2.__iteratees__.push({
      "iteratee": baseIteratee_default(iteratee2, 3),
      "type": type
    });
    result2.__filtered__ = result2.__filtered__ || isFilter;
    return result2;
  };
});
arrayEach_default(["head", "last"], function(methodName, index) {
  var takeName = "take" + (index ? "Right" : "");
  LazyWrapper_default.prototype[methodName] = function() {
    return this[takeName](1).value()[0];
  };
});
arrayEach_default(["initial", "tail"], function(methodName, index) {
  var dropName = "drop" + (index ? "" : "Right");
  LazyWrapper_default.prototype[methodName] = function() {
    return this.__filtered__ ? new LazyWrapper_default(this) : this[dropName](1);
  };
});
LazyWrapper_default.prototype.compact = function() {
  return this.filter(identity_default);
};
LazyWrapper_default.prototype.find = function(predicate) {
  return this.filter(predicate).head();
};
LazyWrapper_default.prototype.findLast = function(predicate) {
  return this.reverse().find(predicate);
};
LazyWrapper_default.prototype.invokeMap = baseRest_default(function(path, args) {
  if (typeof path == "function") {
    return new LazyWrapper_default(this);
  }
  return this.map(function(value) {
    return baseInvoke_default(value, path, args);
  });
});
LazyWrapper_default.prototype.reject = function(predicate) {
  return this.filter(negate_default(baseIteratee_default(predicate)));
};
LazyWrapper_default.prototype.slice = function(start, end) {
  start = toInteger_default(start);
  var result2 = this;
  if (result2.__filtered__ && (start > 0 || end < 0)) {
    return new LazyWrapper_default(result2);
  }
  if (start < 0) {
    result2 = result2.takeRight(-start);
  } else if (start) {
    result2 = result2.drop(start);
  }
  if (end !== void 0) {
    end = toInteger_default(end);
    result2 = end < 0 ? result2.dropRight(-end) : result2.take(end - start);
  }
  return result2;
};
LazyWrapper_default.prototype.takeRightWhile = function(predicate) {
  return this.reverse().takeWhile(predicate).reverse();
};
LazyWrapper_default.prototype.toArray = function() {
  return this.take(MAX_ARRAY_LENGTH7);
};
baseForOwn_default(LazyWrapper_default.prototype, function(func, methodName) {
  var checkIteratee = /^(?:filter|find|map|reject)|While$/.test(methodName), isTaker = /^(?:head|last)$/.test(methodName), lodashFunc = wrapperLodash_default[isTaker ? "take" + (methodName == "last" ? "Right" : "") : methodName], retUnwrapped = isTaker || /^find/.test(methodName);
  if (!lodashFunc) {
    return;
  }
  wrapperLodash_default.prototype[methodName] = function() {
    var value = this.__wrapped__, args = isTaker ? [1] : arguments, isLazy = value instanceof LazyWrapper_default, iteratee2 = args[0], useLazy = isLazy || isArray_default(value);
    var interceptor = function(value2) {
      var result3 = lodashFunc.apply(wrapperLodash_default, arrayPush_default([value2], args));
      return isTaker && chainAll ? result3[0] : result3;
    };
    if (useLazy && checkIteratee && typeof iteratee2 == "function" && iteratee2.length != 1) {
      isLazy = useLazy = false;
    }
    var chainAll = this.__chain__, isHybrid = !!this.__actions__.length, isUnwrapped = retUnwrapped && !chainAll, onlyLazy = isLazy && !isHybrid;
    if (!retUnwrapped && useLazy) {
      value = onlyLazy ? value : new LazyWrapper_default(this);
      var result2 = func.apply(value, args);
      result2.__actions__.push({
        "func": thru_default,
        "args": [interceptor],
        "thisArg": void 0
      });
      return new LodashWrapper_default(result2, chainAll);
    }
    if (isUnwrapped && onlyLazy) {
      return func.apply(this, args);
    }
    result2 = this.thru(interceptor);
    return isUnwrapped ? isTaker ? result2.value()[0] : result2.value() : result2;
  };
});
arrayEach_default(["pop", "push", "shift", "sort", "splice", "unshift"], function(methodName) {
  var func = arrayProto6[methodName], chainName = /^(?:push|sort|unshift)$/.test(methodName) ? "tap" : "thru", retUnwrapped = /^(?:pop|shift)$/.test(methodName);
  wrapperLodash_default.prototype[methodName] = function() {
    var args = arguments;
    if (retUnwrapped && !this.__chain__) {
      var value = this.value();
      return func.apply(isArray_default(value) ? value : [], args);
    }
    return this[chainName](function(value2) {
      return func.apply(isArray_default(value2) ? value2 : [], args);
    });
  };
});
baseForOwn_default(LazyWrapper_default.prototype, function(func, methodName) {
  var lodashFunc = wrapperLodash_default[methodName];
  if (lodashFunc) {
    var key = lodashFunc.name + "";
    if (!hasOwnProperty25.call(realNames_default, key)) {
      realNames_default[key] = [];
    }
    realNames_default[key].push({
      "name": methodName,
      "func": lodashFunc
    });
  }
});
realNames_default[createHybrid_default(void 0, WRAP_BIND_KEY_FLAG7).name] = [{
  "name": "wrapper",
  "func": void 0
}];
LazyWrapper_default.prototype.clone = lazyClone_default;
LazyWrapper_default.prototype.reverse = lazyReverse_default;
LazyWrapper_default.prototype.value = lazyValue_default;
wrapperLodash_default.prototype.at = seq_default_default.at;
wrapperLodash_default.prototype.chain = seq_default_default.wrapperChain;
wrapperLodash_default.prototype.commit = seq_default_default.commit;
wrapperLodash_default.prototype.next = seq_default_default.next;
wrapperLodash_default.prototype.plant = seq_default_default.plant;
wrapperLodash_default.prototype.reverse = seq_default_default.reverse;
wrapperLodash_default.prototype.toJSON = wrapperLodash_default.prototype.valueOf = wrapperLodash_default.prototype.value = seq_default_default.value;
wrapperLodash_default.prototype.first = wrapperLodash_default.prototype.head;
if (symIterator2) {
  wrapperLodash_default.prototype[symIterator2] = seq_default_default.toIterator;
}

// node_modules/parchment/dist/parchment.js
var parchment_exports = {};
__export(parchment_exports, {
  Attributor: () => Attributor,
  AttributorStore: () => AttributorStore$1,
  BlockBlot: () => BlockBlot$1,
  ClassAttributor: () => ClassAttributor$1,
  ContainerBlot: () => ContainerBlot$1,
  EmbedBlot: () => EmbedBlot$1,
  InlineBlot: () => InlineBlot$1,
  LeafBlot: () => LeafBlot$1,
  ParentBlot: () => ParentBlot$1,
  Registry: () => Registry,
  Scope: () => Scope,
  ScrollBlot: () => ScrollBlot$1,
  StyleAttributor: () => StyleAttributor$1,
  TextBlot: () => TextBlot$1
});
var Scope = ((Scope2) => (Scope2[Scope2.TYPE = 3] = "TYPE", Scope2[Scope2.LEVEL = 12] = "LEVEL", Scope2[Scope2.ATTRIBUTE = 13] = "ATTRIBUTE", Scope2[Scope2.BLOT = 14] = "BLOT", Scope2[Scope2.INLINE = 7] = "INLINE", Scope2[Scope2.BLOCK = 11] = "BLOCK", Scope2[Scope2.BLOCK_BLOT = 10] = "BLOCK_BLOT", Scope2[Scope2.INLINE_BLOT = 6] = "INLINE_BLOT", Scope2[Scope2.BLOCK_ATTRIBUTE = 9] = "BLOCK_ATTRIBUTE", Scope2[Scope2.INLINE_ATTRIBUTE = 5] = "INLINE_ATTRIBUTE", Scope2[Scope2.ANY = 15] = "ANY", Scope2))(Scope || {});
var Attributor = class {
  constructor(attrName, keyName, options = {}) {
    this.attrName = attrName, this.keyName = keyName;
    const attributeBit = Scope.TYPE & Scope.ATTRIBUTE;
    this.scope = options.scope != null ? (
      // Ignore type bits, force attribute bit
      options.scope & Scope.LEVEL | attributeBit
    ) : Scope.ATTRIBUTE, options.whitelist != null && (this.whitelist = options.whitelist);
  }
  static keys(node) {
    return Array.from(node.attributes).map((item) => item.name);
  }
  add(node, value) {
    return this.canAdd(node, value) ? (node.setAttribute(this.keyName, value), true) : false;
  }
  canAdd(_node, value) {
    return this.whitelist == null ? true : typeof value == "string" ? this.whitelist.indexOf(value.replace(/["']/g, "")) > -1 : this.whitelist.indexOf(value) > -1;
  }
  remove(node) {
    node.removeAttribute(this.keyName);
  }
  value(node) {
    const value = node.getAttribute(this.keyName);
    return this.canAdd(node, value) && value ? value : "";
  }
};
var ParchmentError = class extends Error {
  constructor(message) {
    message = "[Parchment] " + message, super(message), this.message = message, this.name = this.constructor.name;
  }
};
var _Registry = class _Registry2 {
  constructor() {
    this.attributes = {}, this.classes = {}, this.tags = {}, this.types = {};
  }
  static find(node, bubble = false) {
    if (node == null) return null;
    if (this.blots.has(node)) return this.blots.get(node) || null;
    if (bubble) {
      let parentNode = null;
      try {
        parentNode = node.parentNode;
      } catch {
        return null;
      }
      return this.find(parentNode, bubble);
    }
    return null;
  }
  create(scroll, input, value) {
    const match2 = this.query(input);
    if (match2 == null) throw new ParchmentError(`Unable to create ${input} blot`);
    const blotClass = match2, node = (
      // @ts-expect-error Fix me later
      input instanceof Node || input.nodeType === Node.TEXT_NODE ? input : blotClass.create(value)
    ), blot = new blotClass(scroll, node, value);
    return _Registry2.blots.set(blot.domNode, blot), blot;
  }
  find(node, bubble = false) {
    return _Registry2.find(node, bubble);
  }
  query(query, scope = Scope.ANY) {
    let match2;
    return typeof query == "string" ? match2 = this.types[query] || this.attributes[query] : query instanceof Text || query.nodeType === Node.TEXT_NODE ? match2 = this.types.text : typeof query == "number" ? query & Scope.LEVEL & Scope.BLOCK ? match2 = this.types.block : query & Scope.LEVEL & Scope.INLINE && (match2 = this.types.inline) : query instanceof Element && ((query.getAttribute("class") || "").split(/\s+/).some((name) => (match2 = this.classes[name], !!match2)), match2 = match2 || this.tags[query.tagName]), match2 == null ? null : "scope" in match2 && scope & Scope.LEVEL & match2.scope && scope & Scope.TYPE & match2.scope ? match2 : null;
  }
  register(...definitions) {
    return definitions.map((definition) => {
      const isBlot = "blotName" in definition, isAttr = "attrName" in definition;
      if (!isBlot && !isAttr) throw new ParchmentError("Invalid definition");
      if (isBlot && definition.blotName === "abstract") throw new ParchmentError("Cannot register abstract class");
      const key = isBlot ? definition.blotName : isAttr ? definition.attrName : void 0;
      return this.types[key] = definition, isAttr ? typeof definition.keyName == "string" && (this.attributes[definition.keyName] = definition) : isBlot && (definition.className && (this.classes[definition.className] = definition), definition.tagName && (Array.isArray(definition.tagName) ? definition.tagName = definition.tagName.map((tagName) => tagName.toUpperCase()) : definition.tagName = definition.tagName.toUpperCase(), (Array.isArray(definition.tagName) ? definition.tagName : [definition.tagName]).forEach((tag) => {
        (this.tags[tag] == null || definition.className == null) && (this.tags[tag] = definition);
      }))), definition;
    });
  }
};
_Registry.blots = /* @__PURE__ */ new WeakMap();
var Registry = _Registry;
function match(node, prefix) {
  return (node.getAttribute("class") || "").split(/\s+/).filter((name) => name.indexOf(`${prefix}-`) === 0);
}
var ClassAttributor = class extends Attributor {
  static keys(node) {
    return (node.getAttribute("class") || "").split(/\s+/).map((name) => name.split("-").slice(0, -1).join("-"));
  }
  add(node, value) {
    return this.canAdd(node, value) ? (this.remove(node), node.classList.add(`${this.keyName}-${value}`), true) : false;
  }
  remove(node) {
    match(node, this.keyName).forEach((name) => {
      node.classList.remove(name);
    }), node.classList.length === 0 && node.removeAttribute("class");
  }
  value(node) {
    const value = (match(node, this.keyName)[0] || "").slice(this.keyName.length + 1);
    return this.canAdd(node, value) ? value : "";
  }
};
var ClassAttributor$1 = ClassAttributor;
function camelize(name) {
  const parts = name.split("-"), rest2 = parts.slice(1).map((part) => part[0].toUpperCase() + part.slice(1)).join("");
  return parts[0] + rest2;
}
var StyleAttributor = class extends Attributor {
  static keys(node) {
    return (node.getAttribute("style") || "").split(";").map((value) => value.split(":")[0].trim());
  }
  add(node, value) {
    return this.canAdd(node, value) ? (node.style[camelize(this.keyName)] = value, true) : false;
  }
  remove(node) {
    node.style[camelize(this.keyName)] = "", node.getAttribute("style") || node.removeAttribute("style");
  }
  value(node) {
    const value = node.style[camelize(this.keyName)];
    return this.canAdd(node, value) ? value : "";
  }
};
var StyleAttributor$1 = StyleAttributor;
var AttributorStore = class {
  constructor(domNode) {
    this.attributes = {}, this.domNode = domNode, this.build();
  }
  attribute(attribute, value) {
    value ? attribute.add(this.domNode, value) && (attribute.value(this.domNode) != null ? this.attributes[attribute.attrName] = attribute : delete this.attributes[attribute.attrName]) : (attribute.remove(this.domNode), delete this.attributes[attribute.attrName]);
  }
  build() {
    this.attributes = {};
    const blot = Registry.find(this.domNode);
    if (blot == null) return;
    const attributes = Attributor.keys(this.domNode), classes = ClassAttributor$1.keys(this.domNode), styles = StyleAttributor$1.keys(this.domNode);
    attributes.concat(classes).concat(styles).forEach((name) => {
      const attr = blot.scroll.query(name, Scope.ATTRIBUTE);
      attr instanceof Attributor && (this.attributes[attr.attrName] = attr);
    });
  }
  copy(target) {
    Object.keys(this.attributes).forEach((key) => {
      const value = this.attributes[key].value(this.domNode);
      target.format(key, value);
    });
  }
  move(target) {
    this.copy(target), Object.keys(this.attributes).forEach((key) => {
      this.attributes[key].remove(this.domNode);
    }), this.attributes = {};
  }
  values() {
    return Object.keys(this.attributes).reduce((attributes, name) => (attributes[name] = this.attributes[name].value(this.domNode), attributes), {});
  }
};
var AttributorStore$1 = AttributorStore;
var _ShadowBlot = class _ShadowBlot2 {
  constructor(scroll, domNode) {
    this.scroll = scroll, this.domNode = domNode, Registry.blots.set(domNode, this), this.prev = null, this.next = null;
  }
  static create(rawValue) {
    if (this.tagName == null) throw new ParchmentError("Blot definition missing tagName");
    let node, value;
    return Array.isArray(this.tagName) ? (typeof rawValue == "string" ? (value = rawValue.toUpperCase(), parseInt(value, 10).toString() === value && (value = parseInt(value, 10))) : typeof rawValue == "number" && (value = rawValue), typeof value == "number" ? node = document.createElement(this.tagName[value - 1]) : value && this.tagName.indexOf(value) > -1 ? node = document.createElement(value) : node = document.createElement(this.tagName[0])) : node = document.createElement(this.tagName), this.className && node.classList.add(this.className), node;
  }
  // Hack for accessing inherited static methods
  get statics() {
    return this.constructor;
  }
  attach() {
  }
  clone() {
    const domNode = this.domNode.cloneNode(false);
    return this.scroll.create(domNode);
  }
  detach() {
    this.parent != null && this.parent.removeChild(this), Registry.blots.delete(this.domNode);
  }
  deleteAt(index, length) {
    this.isolate(index, length).remove();
  }
  formatAt(index, length, name, value) {
    const blot = this.isolate(index, length);
    if (this.scroll.query(name, Scope.BLOT) != null && value) blot.wrap(name, value);
    else if (this.scroll.query(name, Scope.ATTRIBUTE) != null) {
      const parent2 = this.scroll.create(this.statics.scope);
      blot.wrap(parent2), parent2.format(name, value);
    }
  }
  insertAt(index, value, def) {
    const blot = def == null ? this.scroll.create("text", value) : this.scroll.create(value, def), ref = this.split(index);
    this.parent.insertBefore(blot, ref || void 0);
  }
  isolate(index, length) {
    const target = this.split(index);
    if (target == null) throw new Error("Attempt to isolate at end");
    return target.split(length), target;
  }
  length() {
    return 1;
  }
  offset(root2 = this.parent) {
    return this.parent == null || this === root2 ? 0 : this.parent.children.offset(this) + this.parent.offset(root2);
  }
  optimize(_context) {
    this.statics.requiredContainer && !(this.parent instanceof this.statics.requiredContainer) && this.wrap(this.statics.requiredContainer.blotName);
  }
  remove() {
    this.domNode.parentNode != null && this.domNode.parentNode.removeChild(this.domNode), this.detach();
  }
  replaceWith(name, value) {
    const replacement = typeof name == "string" ? this.scroll.create(name, value) : name;
    return this.parent != null && (this.parent.insertBefore(replacement, this.next || void 0), this.remove()), replacement;
  }
  split(index, _force) {
    return index === 0 ? this : this.next;
  }
  update(_mutations, _context) {
  }
  wrap(name, value) {
    const wrapper = typeof name == "string" ? this.scroll.create(name, value) : name;
    if (this.parent != null && this.parent.insertBefore(wrapper, this.next || void 0), typeof wrapper.appendChild != "function") throw new ParchmentError(`Cannot wrap ${name}`);
    return wrapper.appendChild(this), wrapper;
  }
};
_ShadowBlot.blotName = "abstract";
var ShadowBlot = _ShadowBlot;
var _LeafBlot = class _LeafBlot2 extends ShadowBlot {
  /**
   * Returns the value represented by domNode if it is this Blot's type
   * No checking that domNode can represent this Blot type is required so
   * applications needing it should check externally before calling.
   */
  static value(_domNode) {
    return true;
  }
  /**
   * Given location represented by node and offset from DOM Selection Range,
   * return index to that location.
   */
  index(node, offset) {
    return this.domNode === node || this.domNode.compareDocumentPosition(node) & Node.DOCUMENT_POSITION_CONTAINED_BY ? Math.min(offset, 1) : -1;
  }
  /**
   * Given index to location within blot, return node and offset representing
   * that location, consumable by DOM Selection Range
   */
  position(index, _inclusive) {
    let offset = Array.from(this.parent.domNode.childNodes).indexOf(this.domNode);
    return index > 0 && (offset += 1), [this.parent.domNode, offset];
  }
  /**
   * Return value represented by this blot
   * Should not change without interaction from API or
   * user change detectable by update()
   */
  value() {
    return {
      [this.statics.blotName]: this.statics.value(this.domNode) || true
    };
  }
};
_LeafBlot.scope = Scope.INLINE_BLOT;
var LeafBlot = _LeafBlot;
var LeafBlot$1 = LeafBlot;
var LinkedList = class {
  constructor() {
    this.head = null, this.tail = null, this.length = 0;
  }
  append(...nodes) {
    if (this.insertBefore(nodes[0], null), nodes.length > 1) {
      const rest2 = nodes.slice(1);
      this.append(...rest2);
    }
  }
  at(index) {
    const next = this.iterator();
    let cur = next();
    for (; cur && index > 0; ) index -= 1, cur = next();
    return cur;
  }
  contains(node) {
    const next = this.iterator();
    let cur = next();
    for (; cur; ) {
      if (cur === node) return true;
      cur = next();
    }
    return false;
  }
  indexOf(node) {
    const next = this.iterator();
    let cur = next(), index = 0;
    for (; cur; ) {
      if (cur === node) return index;
      index += 1, cur = next();
    }
    return -1;
  }
  insertBefore(node, refNode) {
    node != null && (this.remove(node), node.next = refNode, refNode != null ? (node.prev = refNode.prev, refNode.prev != null && (refNode.prev.next = node), refNode.prev = node, refNode === this.head && (this.head = node)) : this.tail != null ? (this.tail.next = node, node.prev = this.tail, this.tail = node) : (node.prev = null, this.head = this.tail = node), this.length += 1);
  }
  offset(target) {
    let index = 0, cur = this.head;
    for (; cur != null; ) {
      if (cur === target) return index;
      index += cur.length(), cur = cur.next;
    }
    return -1;
  }
  remove(node) {
    this.contains(node) && (node.prev != null && (node.prev.next = node.next), node.next != null && (node.next.prev = node.prev), node === this.head && (this.head = node.next), node === this.tail && (this.tail = node.prev), this.length -= 1);
  }
  iterator(curNode = this.head) {
    return () => {
      const ret = curNode;
      return curNode != null && (curNode = curNode.next), ret;
    };
  }
  find(index, inclusive = false) {
    const next = this.iterator();
    let cur = next();
    for (; cur; ) {
      const length = cur.length();
      if (index < length || inclusive && index === length && (cur.next == null || cur.next.length() !== 0)) return [cur, index];
      index -= length, cur = next();
    }
    return [null, 0];
  }
  forEach(callback) {
    const next = this.iterator();
    let cur = next();
    for (; cur; ) callback(cur), cur = next();
  }
  forEachAt(index, length, callback) {
    if (length <= 0) return;
    const [startNode, offset] = this.find(index);
    let curIndex = index - offset;
    const next = this.iterator(startNode);
    let cur = next();
    for (; cur && curIndex < index + length; ) {
      const curLength = cur.length();
      index > curIndex ? callback(cur, index - curIndex, Math.min(length, curIndex + curLength - index)) : callback(cur, 0, Math.min(curLength, index + length - curIndex)), curIndex += curLength, cur = next();
    }
  }
  map(callback) {
    return this.reduce((memo, cur) => (memo.push(callback(cur)), memo), []);
  }
  reduce(callback, memo) {
    const next = this.iterator();
    let cur = next();
    for (; cur; ) memo = callback(memo, cur), cur = next();
    return memo;
  }
};
function makeAttachedBlot(node, scroll) {
  const found = scroll.find(node);
  if (found) return found;
  try {
    return scroll.create(node);
  } catch {
    const blot = scroll.create(Scope.INLINE);
    return Array.from(node.childNodes).forEach((child) => {
      blot.domNode.appendChild(child);
    }), node.parentNode && node.parentNode.replaceChild(blot.domNode, node), blot.attach(), blot;
  }
}
var _ParentBlot = class _ParentBlot2 extends ShadowBlot {
  constructor(scroll, domNode) {
    super(scroll, domNode), this.uiNode = null, this.build();
  }
  appendChild(other) {
    this.insertBefore(other);
  }
  attach() {
    super.attach(), this.children.forEach((child) => {
      child.attach();
    });
  }
  attachUI(node) {
    this.uiNode != null && this.uiNode.remove(), this.uiNode = node, _ParentBlot2.uiClass && this.uiNode.classList.add(_ParentBlot2.uiClass), this.uiNode.setAttribute("contenteditable", "false"), this.domNode.insertBefore(this.uiNode, this.domNode.firstChild);
  }
  /**
   * Called during construction, should fill its own children LinkedList.
   */
  build() {
    this.children = new LinkedList(), Array.from(this.domNode.childNodes).filter((node) => node !== this.uiNode).reverse().forEach((node) => {
      try {
        const child = makeAttachedBlot(node, this.scroll);
        this.insertBefore(child, this.children.head || void 0);
      } catch (err) {
        if (err instanceof ParchmentError) return;
        throw err;
      }
    });
  }
  deleteAt(index, length) {
    if (index === 0 && length === this.length()) return this.remove();
    this.children.forEachAt(index, length, (child, offset, childLength) => {
      child.deleteAt(offset, childLength);
    });
  }
  descendant(criteria, index = 0) {
    const [child, offset] = this.children.find(index);
    return criteria.blotName == null && criteria(child) || criteria.blotName != null && child instanceof criteria ? [child, offset] : child instanceof _ParentBlot2 ? child.descendant(criteria, offset) : [null, -1];
  }
  descendants(criteria, index = 0, length = Number.MAX_VALUE) {
    let descendants = [], lengthLeft = length;
    return this.children.forEachAt(index, length, (child, childIndex, childLength) => {
      (criteria.blotName == null && criteria(child) || criteria.blotName != null && child instanceof criteria) && descendants.push(child), child instanceof _ParentBlot2 && (descendants = descendants.concat(child.descendants(criteria, childIndex, lengthLeft))), lengthLeft -= childLength;
    }), descendants;
  }
  detach() {
    this.children.forEach((child) => {
      child.detach();
    }), super.detach();
  }
  enforceAllowedChildren() {
    let done = false;
    this.children.forEach((child) => {
      done || this.statics.allowedChildren.some((def) => child instanceof def) || (child.statics.scope === Scope.BLOCK_BLOT ? (child.next != null && this.splitAfter(child), child.prev != null && this.splitAfter(child.prev), child.parent.unwrap(), done = true) : child instanceof _ParentBlot2 ? child.unwrap() : child.remove());
    });
  }
  formatAt(index, length, name, value) {
    this.children.forEachAt(index, length, (child, offset, childLength) => {
      child.formatAt(offset, childLength, name, value);
    });
  }
  insertAt(index, value, def) {
    const [child, offset] = this.children.find(index);
    if (child) child.insertAt(offset, value, def);
    else {
      const blot = def == null ? this.scroll.create("text", value) : this.scroll.create(value, def);
      this.appendChild(blot);
    }
  }
  insertBefore(childBlot, refBlot) {
    childBlot.parent != null && childBlot.parent.children.remove(childBlot);
    let refDomNode = null;
    this.children.insertBefore(childBlot, refBlot || null), childBlot.parent = this, refBlot != null && (refDomNode = refBlot.domNode), (this.domNode.parentNode !== childBlot.domNode || this.domNode.nextSibling !== refDomNode) && this.domNode.insertBefore(childBlot.domNode, refDomNode), childBlot.attach();
  }
  length() {
    return this.children.reduce((memo, child) => memo + child.length(), 0);
  }
  moveChildren(targetParent, refNode) {
    this.children.forEach((child) => {
      targetParent.insertBefore(child, refNode);
    });
  }
  optimize(context) {
    if (super.optimize(context), this.enforceAllowedChildren(), this.uiNode != null && this.uiNode !== this.domNode.firstChild && this.domNode.insertBefore(this.uiNode, this.domNode.firstChild), this.children.length === 0) if (this.statics.defaultChild != null) {
      const child = this.scroll.create(this.statics.defaultChild.blotName);
      this.appendChild(child);
    } else this.remove();
  }
  path(index, inclusive = false) {
    const [child, offset] = this.children.find(index, inclusive), position = [[this, index]];
    return child instanceof _ParentBlot2 ? position.concat(child.path(offset, inclusive)) : (child != null && position.push([child, offset]), position);
  }
  removeChild(child) {
    this.children.remove(child);
  }
  replaceWith(name, value) {
    const replacement = typeof name == "string" ? this.scroll.create(name, value) : name;
    return replacement instanceof _ParentBlot2 && this.moveChildren(replacement), super.replaceWith(replacement);
  }
  split(index, force = false) {
    if (!force) {
      if (index === 0) return this;
      if (index === this.length()) return this.next;
    }
    const after2 = this.clone();
    return this.parent && this.parent.insertBefore(after2, this.next || void 0), this.children.forEachAt(index, this.length(), (child, offset, _length) => {
      const split2 = child.split(offset, force);
      split2 != null && after2.appendChild(split2);
    }), after2;
  }
  splitAfter(child) {
    const after2 = this.clone();
    for (; child.next != null; ) after2.appendChild(child.next);
    return this.parent && this.parent.insertBefore(after2, this.next || void 0), after2;
  }
  unwrap() {
    this.parent && this.moveChildren(this.parent, this.next || void 0), this.remove();
  }
  update(mutations, _context) {
    const addedNodes = [], removedNodes = [];
    mutations.forEach((mutation) => {
      mutation.target === this.domNode && mutation.type === "childList" && (addedNodes.push(...mutation.addedNodes), removedNodes.push(...mutation.removedNodes));
    }), removedNodes.forEach((node) => {
      if (node.parentNode != null && // @ts-expect-error Fix me later
      node.tagName !== "IFRAME" && document.body.compareDocumentPosition(node) & Node.DOCUMENT_POSITION_CONTAINED_BY) return;
      const blot = this.scroll.find(node);
      blot != null && (blot.domNode.parentNode == null || blot.domNode.parentNode === this.domNode) && blot.detach();
    }), addedNodes.filter((node) => node.parentNode === this.domNode && node !== this.uiNode).sort((a, b) => a === b ? 0 : a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING ? 1 : -1).forEach((node) => {
      let refBlot = null;
      node.nextSibling != null && (refBlot = this.scroll.find(node.nextSibling));
      const blot = makeAttachedBlot(node, this.scroll);
      (blot.next !== refBlot || blot.next == null) && (blot.parent != null && blot.parent.removeChild(this), this.insertBefore(blot, refBlot || void 0));
    }), this.enforceAllowedChildren();
  }
};
_ParentBlot.uiClass = "";
var ParentBlot = _ParentBlot;
var ParentBlot$1 = ParentBlot;
function isEqual2(obj1, obj2) {
  if (Object.keys(obj1).length !== Object.keys(obj2).length) return false;
  for (const prop in obj1) if (obj1[prop] !== obj2[prop]) return false;
  return true;
}
var _InlineBlot = class _InlineBlot2 extends ParentBlot$1 {
  static create(value) {
    return super.create(value);
  }
  static formats(domNode, scroll) {
    const match2 = scroll.query(_InlineBlot2.blotName);
    if (!(match2 != null && domNode.tagName === match2.tagName)) {
      if (typeof this.tagName == "string") return true;
      if (Array.isArray(this.tagName)) return domNode.tagName.toLowerCase();
    }
  }
  constructor(scroll, domNode) {
    super(scroll, domNode), this.attributes = new AttributorStore$1(this.domNode);
  }
  format(name, value) {
    if (name === this.statics.blotName && !value) this.children.forEach((child) => {
      child instanceof _InlineBlot2 || (child = child.wrap(_InlineBlot2.blotName, true)), this.attributes.copy(child);
    }), this.unwrap();
    else {
      const format = this.scroll.query(name, Scope.INLINE);
      if (format == null) return;
      format instanceof Attributor ? this.attributes.attribute(format, value) : value && (name !== this.statics.blotName || this.formats()[name] !== value) && this.replaceWith(name, value);
    }
  }
  formats() {
    const formats = this.attributes.values(), format = this.statics.formats(this.domNode, this.scroll);
    return format != null && (formats[this.statics.blotName] = format), formats;
  }
  formatAt(index, length, name, value) {
    this.formats()[name] != null || this.scroll.query(name, Scope.ATTRIBUTE) ? this.isolate(index, length).format(name, value) : super.formatAt(index, length, name, value);
  }
  optimize(context) {
    super.optimize(context);
    const formats = this.formats();
    if (Object.keys(formats).length === 0) return this.unwrap();
    const next = this.next;
    next instanceof _InlineBlot2 && next.prev === this && isEqual2(formats, next.formats()) && (next.moveChildren(this), next.remove());
  }
  replaceWith(name, value) {
    const replacement = super.replaceWith(name, value);
    return this.attributes.copy(replacement), replacement;
  }
  update(mutations, context) {
    super.update(mutations, context), mutations.some((mutation) => mutation.target === this.domNode && mutation.type === "attributes") && this.attributes.build();
  }
  wrap(name, value) {
    const wrapper = super.wrap(name, value);
    return wrapper instanceof _InlineBlot2 && this.attributes.move(wrapper), wrapper;
  }
};
_InlineBlot.allowedChildren = [_InlineBlot, LeafBlot$1], _InlineBlot.blotName = "inline", _InlineBlot.scope = Scope.INLINE_BLOT, _InlineBlot.tagName = "SPAN";
var InlineBlot = _InlineBlot;
var InlineBlot$1 = InlineBlot;
var _BlockBlot = class _BlockBlot2 extends ParentBlot$1 {
  static create(value) {
    return super.create(value);
  }
  static formats(domNode, scroll) {
    const match2 = scroll.query(_BlockBlot2.blotName);
    if (!(match2 != null && domNode.tagName === match2.tagName)) {
      if (typeof this.tagName == "string") return true;
      if (Array.isArray(this.tagName)) return domNode.tagName.toLowerCase();
    }
  }
  constructor(scroll, domNode) {
    super(scroll, domNode), this.attributes = new AttributorStore$1(this.domNode);
  }
  format(name, value) {
    const format = this.scroll.query(name, Scope.BLOCK);
    format != null && (format instanceof Attributor ? this.attributes.attribute(format, value) : name === this.statics.blotName && !value ? this.replaceWith(_BlockBlot2.blotName) : value && (name !== this.statics.blotName || this.formats()[name] !== value) && this.replaceWith(name, value));
  }
  formats() {
    const formats = this.attributes.values(), format = this.statics.formats(this.domNode, this.scroll);
    return format != null && (formats[this.statics.blotName] = format), formats;
  }
  formatAt(index, length, name, value) {
    this.scroll.query(name, Scope.BLOCK) != null ? this.format(name, value) : super.formatAt(index, length, name, value);
  }
  insertAt(index, value, def) {
    if (def == null || this.scroll.query(value, Scope.INLINE) != null) super.insertAt(index, value, def);
    else {
      const after2 = this.split(index);
      if (after2 != null) {
        const blot = this.scroll.create(value, def);
        after2.parent.insertBefore(blot, after2);
      } else throw new Error("Attempt to insertAt after block boundaries");
    }
  }
  replaceWith(name, value) {
    const replacement = super.replaceWith(name, value);
    return this.attributes.copy(replacement), replacement;
  }
  update(mutations, context) {
    super.update(mutations, context), mutations.some((mutation) => mutation.target === this.domNode && mutation.type === "attributes") && this.attributes.build();
  }
};
_BlockBlot.blotName = "block", _BlockBlot.scope = Scope.BLOCK_BLOT, _BlockBlot.tagName = "P", _BlockBlot.allowedChildren = [InlineBlot$1, _BlockBlot, LeafBlot$1];
var BlockBlot = _BlockBlot;
var BlockBlot$1 = BlockBlot;
var _ContainerBlot = class _ContainerBlot2 extends ParentBlot$1 {
  checkMerge() {
    return this.next !== null && this.next.statics.blotName === this.statics.blotName;
  }
  deleteAt(index, length) {
    super.deleteAt(index, length), this.enforceAllowedChildren();
  }
  formatAt(index, length, name, value) {
    super.formatAt(index, length, name, value), this.enforceAllowedChildren();
  }
  insertAt(index, value, def) {
    super.insertAt(index, value, def), this.enforceAllowedChildren();
  }
  optimize(context) {
    super.optimize(context), this.children.length > 0 && this.next != null && this.checkMerge() && (this.next.moveChildren(this), this.next.remove());
  }
};
_ContainerBlot.blotName = "container", _ContainerBlot.scope = Scope.BLOCK_BLOT;
var ContainerBlot = _ContainerBlot;
var ContainerBlot$1 = ContainerBlot;
var EmbedBlot = class extends LeafBlot$1 {
  static formats(_domNode, _scroll) {
  }
  format(name, value) {
    super.formatAt(0, this.length(), name, value);
  }
  formatAt(index, length, name, value) {
    index === 0 && length === this.length() ? this.format(name, value) : super.formatAt(index, length, name, value);
  }
  formats() {
    return this.statics.formats(this.domNode, this.scroll);
  }
};
var EmbedBlot$1 = EmbedBlot;
var OBSERVER_CONFIG = {
  attributes: true,
  characterData: true,
  characterDataOldValue: true,
  childList: true,
  subtree: true
};
var MAX_OPTIMIZE_ITERATIONS = 100;
var _ScrollBlot = class _ScrollBlot2 extends ParentBlot$1 {
  constructor(registry, node) {
    super(null, node), this.registry = registry, this.scroll = this, this.build(), this.observer = new MutationObserver((mutations) => {
      this.update(mutations);
    }), this.observer.observe(this.domNode, OBSERVER_CONFIG), this.attach();
  }
  create(input, value) {
    return this.registry.create(this, input, value);
  }
  find(node, bubble = false) {
    const blot = this.registry.find(node, bubble);
    return blot ? blot.scroll === this ? blot : bubble ? this.find(blot.scroll.domNode.parentNode, true) : null : null;
  }
  query(query, scope = Scope.ANY) {
    return this.registry.query(query, scope);
  }
  register(...definitions) {
    return this.registry.register(...definitions);
  }
  build() {
    this.scroll != null && super.build();
  }
  detach() {
    super.detach(), this.observer.disconnect();
  }
  deleteAt(index, length) {
    this.update(), index === 0 && length === this.length() ? this.children.forEach((child) => {
      child.remove();
    }) : super.deleteAt(index, length);
  }
  formatAt(index, length, name, value) {
    this.update(), super.formatAt(index, length, name, value);
  }
  insertAt(index, value, def) {
    this.update(), super.insertAt(index, value, def);
  }
  optimize(mutations = [], context = {}) {
    super.optimize(context);
    const mutationsMap = context.mutationsMap || /* @__PURE__ */ new WeakMap();
    let records = Array.from(this.observer.takeRecords());
    for (; records.length > 0; ) mutations.push(records.pop());
    const mark = (blot, markParent = true) => {
      blot == null || blot === this || blot.domNode.parentNode != null && (mutationsMap.has(blot.domNode) || mutationsMap.set(blot.domNode, []), markParent && mark(blot.parent));
    }, optimize = (blot) => {
      mutationsMap.has(blot.domNode) && (blot instanceof ParentBlot$1 && blot.children.forEach(optimize), mutationsMap.delete(blot.domNode), blot.optimize(context));
    };
    let remaining = mutations;
    for (let i = 0; remaining.length > 0; i += 1) {
      if (i >= MAX_OPTIMIZE_ITERATIONS) throw new Error("[Parchment] Maximum optimize iterations reached");
      for (remaining.forEach((mutation) => {
        const blot = this.find(mutation.target, true);
        blot != null && (blot.domNode === mutation.target && (mutation.type === "childList" ? (mark(this.find(mutation.previousSibling, false)), Array.from(mutation.addedNodes).forEach((node) => {
          const child = this.find(node, false);
          mark(child, false), child instanceof ParentBlot$1 && child.children.forEach((grandChild) => {
            mark(grandChild, false);
          });
        })) : mutation.type === "attributes" && mark(blot.prev)), mark(blot));
      }), this.children.forEach(optimize), remaining = Array.from(this.observer.takeRecords()), records = remaining.slice(); records.length > 0; ) mutations.push(records.pop());
    }
  }
  update(mutations, context = {}) {
    mutations = mutations || this.observer.takeRecords();
    const mutationsMap = /* @__PURE__ */ new WeakMap();
    mutations.map((mutation) => {
      const blot = this.find(mutation.target, true);
      return blot == null ? null : mutationsMap.has(blot.domNode) ? (mutationsMap.get(blot.domNode).push(mutation), null) : (mutationsMap.set(blot.domNode, [mutation]), blot);
    }).forEach((blot) => {
      blot != null && blot !== this && mutationsMap.has(blot.domNode) && blot.update(mutationsMap.get(blot.domNode) || [], context);
    }), context.mutationsMap = mutationsMap, mutationsMap.has(this.domNode) && super.update(mutationsMap.get(this.domNode), context), this.optimize(mutations, context);
  }
};
_ScrollBlot.blotName = "scroll", _ScrollBlot.defaultChild = BlockBlot$1, _ScrollBlot.allowedChildren = [BlockBlot$1, ContainerBlot$1], _ScrollBlot.scope = Scope.BLOCK_BLOT, _ScrollBlot.tagName = "DIV";
var ScrollBlot = _ScrollBlot;
var ScrollBlot$1 = ScrollBlot;
var _TextBlot = class _TextBlot2 extends LeafBlot$1 {
  static create(value) {
    return document.createTextNode(value);
  }
  static value(domNode) {
    return domNode.data;
  }
  constructor(scroll, node) {
    super(scroll, node), this.text = this.statics.value(this.domNode);
  }
  deleteAt(index, length) {
    this.domNode.data = this.text = this.text.slice(0, index) + this.text.slice(index + length);
  }
  index(node, offset) {
    return this.domNode === node ? offset : -1;
  }
  insertAt(index, value, def) {
    def == null ? (this.text = this.text.slice(0, index) + value + this.text.slice(index), this.domNode.data = this.text) : super.insertAt(index, value, def);
  }
  length() {
    return this.text.length;
  }
  optimize(context) {
    super.optimize(context), this.text = this.statics.value(this.domNode), this.text.length === 0 ? this.remove() : this.next instanceof _TextBlot2 && this.next.prev === this && (this.insertAt(this.length(), this.next.value()), this.next.remove());
  }
  position(index, _inclusive = false) {
    return [this.domNode, index];
  }
  split(index, force = false) {
    if (!force) {
      if (index === 0) return this;
      if (index === this.length()) return this.next;
    }
    const after2 = this.scroll.create(this.domNode.splitText(index));
    return this.parent.insertBefore(after2, this.next || void 0), this.text = this.statics.value(this.domNode), after2;
  }
  update(mutations, _context) {
    mutations.some((mutation) => mutation.type === "characterData" && mutation.target === this.domNode) && (this.text = this.statics.value(this.domNode));
  }
  value() {
    return this.text;
  }
};
_TextBlot.blotName = "text", _TextBlot.scope = Scope.INLINE_BLOT;
var TextBlot = _TextBlot;
var TextBlot$1 = TextBlot;

// node_modules/quill/core/quill.js
var import_quill_delta3 = __toESM(require_Delta(), 1);

// node_modules/quill/core/editor.js
var import_quill_delta2 = __toESM(require_Delta(), 1);

// node_modules/quill/blots/block.js
var import_quill_delta = __toESM(require_Delta(), 1);

// node_modules/quill/blots/break.js
var Break = class extends EmbedBlot$1 {
  static value() {
    return void 0;
  }
  optimize() {
    if (this.prev || this.next) {
      this.remove();
    }
  }
  length() {
    return 0;
  }
  value() {
    return "";
  }
};
Break.blotName = "break";
Break.tagName = "BR";
var break_default = Break;

// node_modules/quill/blots/text.js
var Text2 = class extends TextBlot$1 {
};
var entityMap = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;"
};
function escapeText(text) {
  return text.replace(/[&<>"']/g, (s) => entityMap[s]);
}

// node_modules/quill/blots/inline.js
var Inline = class _Inline extends InlineBlot$1 {
  static allowedChildren = [_Inline, break_default, EmbedBlot$1, Text2];
  // Lower index means deeper in the DOM tree, since not found (-1) is for embeds
  static order = [
    "cursor",
    "inline",
    // Must be lower
    "link",
    // Chrome wants <a> to be lower
    "underline",
    "strike",
    "italic",
    "bold",
    "script",
    "code"
    // Must be higher
  ];
  static compare(self2, other) {
    const selfIndex = _Inline.order.indexOf(self2);
    const otherIndex = _Inline.order.indexOf(other);
    if (selfIndex >= 0 || otherIndex >= 0) {
      return selfIndex - otherIndex;
    }
    if (self2 === other) {
      return 0;
    }
    if (self2 < other) {
      return -1;
    }
    return 1;
  }
  formatAt(index, length, name, value) {
    if (_Inline.compare(this.statics.blotName, name) < 0 && this.scroll.query(name, Scope.BLOT)) {
      const blot = this.isolate(index, length);
      if (value) {
        blot.wrap(name, value);
      }
    } else {
      super.formatAt(index, length, name, value);
    }
  }
  optimize(context) {
    super.optimize(context);
    if (this.parent instanceof _Inline && _Inline.compare(this.statics.blotName, this.parent.statics.blotName) > 0) {
      const parent2 = this.parent.isolate(this.offset(), this.length());
      this.moveChildren(parent2);
      parent2.wrap(this);
    }
  }
};
var inline_default = Inline;

// node_modules/quill/blots/block.js
var NEWLINE_LENGTH = 1;
var Block = class extends BlockBlot$1 {
  cache = {};
  delta() {
    if (this.cache.delta == null) {
      this.cache.delta = blockDelta(this);
    }
    return this.cache.delta;
  }
  deleteAt(index, length) {
    super.deleteAt(index, length);
    this.cache = {};
  }
  formatAt(index, length, name, value) {
    if (length <= 0) return;
    if (this.scroll.query(name, Scope.BLOCK)) {
      if (index + length === this.length()) {
        this.format(name, value);
      }
    } else {
      super.formatAt(index, Math.min(length, this.length() - index - 1), name, value);
    }
    this.cache = {};
  }
  insertAt(index, value, def) {
    if (def != null) {
      super.insertAt(index, value, def);
      this.cache = {};
      return;
    }
    if (value.length === 0) return;
    const lines = value.split("\n");
    const text = lines.shift();
    if (text.length > 0) {
      if (index < this.length() - 1 || this.children.tail == null) {
        super.insertAt(Math.min(index, this.length() - 1), text);
      } else {
        this.children.tail.insertAt(this.children.tail.length(), text);
      }
      this.cache = {};
    }
    let block = this;
    lines.reduce((lineIndex, line) => {
      block = block.split(lineIndex, true);
      block.insertAt(0, line);
      return line.length;
    }, index + text.length);
  }
  insertBefore(blot, ref) {
    const {
      head: head2
    } = this.children;
    super.insertBefore(blot, ref);
    if (head2 instanceof break_default) {
      head2.remove();
    }
    this.cache = {};
  }
  length() {
    if (this.cache.length == null) {
      this.cache.length = super.length() + NEWLINE_LENGTH;
    }
    return this.cache.length;
  }
  moveChildren(target, ref) {
    super.moveChildren(target, ref);
    this.cache = {};
  }
  optimize(context) {
    super.optimize(context);
    this.cache = {};
  }
  path(index) {
    return super.path(index, true);
  }
  removeChild(child) {
    super.removeChild(child);
    this.cache = {};
  }
  split(index) {
    let force = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : false;
    if (force && (index === 0 || index >= this.length() - NEWLINE_LENGTH)) {
      const clone2 = this.clone();
      if (index === 0) {
        this.parent.insertBefore(clone2, this);
        return this;
      }
      this.parent.insertBefore(clone2, this.next);
      return clone2;
    }
    const next = super.split(index, force);
    this.cache = {};
    return next;
  }
};
Block.blotName = "block";
Block.tagName = "P";
Block.defaultChild = break_default;
Block.allowedChildren = [break_default, inline_default, EmbedBlot$1, Text2];
var BlockEmbed = class extends EmbedBlot$1 {
  attach() {
    super.attach();
    this.attributes = new AttributorStore$1(this.domNode);
  }
  delta() {
    return new import_quill_delta.default().insert(this.value(), __spreadValues(__spreadValues({}, this.formats()), this.attributes.values()));
  }
  format(name, value) {
    const attribute = this.scroll.query(name, Scope.BLOCK_ATTRIBUTE);
    if (attribute != null) {
      this.attributes.attribute(attribute, value);
    }
  }
  formatAt(index, length, name, value) {
    this.format(name, value);
  }
  insertAt(index, value, def) {
    if (def != null) {
      super.insertAt(index, value, def);
      return;
    }
    const lines = value.split("\n");
    const text = lines.pop();
    const blocks = lines.map((line) => {
      const block = this.scroll.create(Block.blotName);
      block.insertAt(0, line);
      return block;
    });
    const ref = this.split(index);
    blocks.forEach((block) => {
      this.parent.insertBefore(block, ref);
    });
    if (text) {
      this.parent.insertBefore(this.scroll.create("text", text), ref);
    }
  }
};
BlockEmbed.scope = Scope.BLOCK_BLOT;
function blockDelta(blot) {
  let filter2 = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : true;
  return blot.descendants(LeafBlot$1).reduce((delta, leaf) => {
    if (leaf.length() === 0) {
      return delta;
    }
    return delta.insert(leaf.value(), bubbleFormats(leaf, {}, filter2));
  }, new import_quill_delta.default()).insert("\n", bubbleFormats(blot));
}
function bubbleFormats(blot) {
  let formats = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : {};
  let filter2 = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : true;
  if (blot == null) return formats;
  if ("formats" in blot && typeof blot.formats === "function") {
    formats = __spreadValues(__spreadValues({}, formats), blot.formats());
    if (filter2) {
      delete formats["code-token"];
    }
  }
  if (blot.parent == null || blot.parent.statics.blotName === "scroll" || blot.parent.statics.scope !== blot.statics.scope) {
    return formats;
  }
  return bubbleFormats(blot.parent, formats, filter2);
}

// node_modules/quill/blots/cursor.js
var Cursor = class _Cursor extends EmbedBlot$1 {
  static blotName = "cursor";
  static className = "ql-cursor";
  static tagName = "span";
  static CONTENTS = "\uFEFF";
  // Zero width no break space
  static value() {
    return void 0;
  }
  constructor(scroll, domNode, selection) {
    super(scroll, domNode);
    this.selection = selection;
    this.textNode = document.createTextNode(_Cursor.CONTENTS);
    this.domNode.appendChild(this.textNode);
    this.savedLength = 0;
  }
  detach() {
    if (this.parent != null) this.parent.removeChild(this);
  }
  format(name, value) {
    if (this.savedLength !== 0) {
      super.format(name, value);
      return;
    }
    let target = this;
    let index = 0;
    while (target != null && target.statics.scope !== Scope.BLOCK_BLOT) {
      index += target.offset(target.parent);
      target = target.parent;
    }
    if (target != null) {
      this.savedLength = _Cursor.CONTENTS.length;
      target.optimize();
      target.formatAt(index, _Cursor.CONTENTS.length, name, value);
      this.savedLength = 0;
    }
  }
  index(node, offset) {
    if (node === this.textNode) return 0;
    return super.index(node, offset);
  }
  length() {
    return this.savedLength;
  }
  position() {
    return [this.textNode, this.textNode.data.length];
  }
  remove() {
    super.remove();
    this.parent = null;
  }
  restore() {
    if (this.selection.composing || this.parent == null) return null;
    const range2 = this.selection.getNativeRange();
    while (this.domNode.lastChild != null && this.domNode.lastChild !== this.textNode) {
      this.domNode.parentNode.insertBefore(this.domNode.lastChild, this.domNode);
    }
    const prevTextBlot = this.prev instanceof Text2 ? this.prev : null;
    const prevTextLength = prevTextBlot ? prevTextBlot.length() : 0;
    const nextTextBlot = this.next instanceof Text2 ? this.next : null;
    const nextText = nextTextBlot ? nextTextBlot.text : "";
    const {
      textNode
    } = this;
    const newText = textNode.data.split(_Cursor.CONTENTS).join("");
    textNode.data = _Cursor.CONTENTS;
    let mergedTextBlot;
    if (prevTextBlot) {
      mergedTextBlot = prevTextBlot;
      if (newText || nextTextBlot) {
        prevTextBlot.insertAt(prevTextBlot.length(), newText + nextText);
        if (nextTextBlot) {
          nextTextBlot.remove();
        }
      }
    } else if (nextTextBlot) {
      mergedTextBlot = nextTextBlot;
      nextTextBlot.insertAt(0, newText);
    } else {
      const newTextNode = document.createTextNode(newText);
      mergedTextBlot = this.scroll.create(newTextNode);
      this.parent.insertBefore(mergedTextBlot, this);
    }
    this.remove();
    if (range2) {
      const remapOffset = (node, offset) => {
        if (prevTextBlot && node === prevTextBlot.domNode) {
          return offset;
        }
        if (node === textNode) {
          return prevTextLength + offset - 1;
        }
        if (nextTextBlot && node === nextTextBlot.domNode) {
          return prevTextLength + newText.length + offset;
        }
        return null;
      };
      const start = remapOffset(range2.start.node, range2.start.offset);
      const end = remapOffset(range2.end.node, range2.end.offset);
      if (start !== null && end !== null) {
        return {
          startNode: mergedTextBlot.domNode,
          startOffset: start,
          endNode: mergedTextBlot.domNode,
          endOffset: end
        };
      }
    }
    return null;
  }
  update(mutations, context) {
    if (mutations.some((mutation) => {
      return mutation.type === "characterData" && mutation.target === this.textNode;
    })) {
      const range2 = this.restore();
      if (range2) context.range = range2;
    }
  }
  // Avoid .ql-cursor being a descendant of `<a/>`.
  // The reason is Safari pushes down `<a/>` on text insertion.
  // That will cause DOM nodes not sync with the model.
  //
  // For example ({I} is the caret), given the markup:
  //    <a><span class="ql-cursor">\uFEFF{I}</span></a>
  // When typing a char "x", `<a/>` will be pushed down inside the `<span>` first:
  //    <span class="ql-cursor"><a>\uFEFF{I}</a></span>
  // And then "x" will be inserted after `<a/>`:
  //    <span class="ql-cursor"><a>\uFEFF</a>d{I}</span>
  optimize(context) {
    super.optimize(context);
    let {
      parent: parent2
    } = this;
    while (parent2) {
      if (parent2.domNode.tagName === "A") {
        this.savedLength = _Cursor.CONTENTS.length;
        parent2.isolate(this.offset(parent2), this.length()).unwrap();
        this.savedLength = 0;
        break;
      }
      parent2 = parent2.parent;
    }
  }
  value() {
    return "";
  }
};
var cursor_default = Cursor;

// node_modules/quill/node_modules/eventemitter3/index.mjs
var import_index = __toESM(require_eventemitter3(), 1);

// node_modules/quill/core/instances.js
var instances_default = /* @__PURE__ */ new WeakMap();

// node_modules/quill/core/logger.js
var levels = ["error", "warn", "log", "info"];
var level = "warn";
function debug(method2) {
  if (level) {
    if (levels.indexOf(method2) <= levels.indexOf(level)) {
      for (var _len = arguments.length, args = new Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
        args[_key - 1] = arguments[_key];
      }
      console[method2](...args);
    }
  }
}
function namespace(ns) {
  return levels.reduce((logger, method2) => {
    logger[method2] = debug.bind(console, method2, ns);
    return logger;
  }, {});
}
namespace.level = (newLevel) => {
  level = newLevel;
};
debug.level = namespace.level;
var logger_default = namespace;

// node_modules/quill/core/emitter.js
var debug2 = logger_default("quill:events");
var EVENTS = ["selectionchange", "mousedown", "mouseup", "click"];
EVENTS.forEach((eventName) => {
  document.addEventListener(eventName, function() {
    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }
    Array.from(document.querySelectorAll(".ql-container")).forEach((node) => {
      const quill = instances_default.get(node);
      if (quill && quill.emitter) {
        quill.emitter.handleDOM(...args);
      }
    });
  });
});
var Emitter = class extends import_index.default {
  static events = {
    EDITOR_CHANGE: "editor-change",
    SCROLL_BEFORE_UPDATE: "scroll-before-update",
    SCROLL_BLOT_MOUNT: "scroll-blot-mount",
    SCROLL_BLOT_UNMOUNT: "scroll-blot-unmount",
    SCROLL_OPTIMIZE: "scroll-optimize",
    SCROLL_UPDATE: "scroll-update",
    SCROLL_EMBED_UPDATE: "scroll-embed-update",
    SELECTION_CHANGE: "selection-change",
    TEXT_CHANGE: "text-change",
    COMPOSITION_BEFORE_START: "composition-before-start",
    COMPOSITION_START: "composition-start",
    COMPOSITION_BEFORE_END: "composition-before-end",
    COMPOSITION_END: "composition-end"
  };
  static sources = {
    API: "api",
    SILENT: "silent",
    USER: "user"
  };
  constructor() {
    super();
    this.domListeners = {};
    this.on("error", debug2.error);
  }
  emit() {
    for (var _len2 = arguments.length, args = new Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
      args[_key2] = arguments[_key2];
    }
    debug2.log.call(debug2, ...args);
    return super.emit(...args);
  }
  handleDOM(event) {
    for (var _len3 = arguments.length, args = new Array(_len3 > 1 ? _len3 - 1 : 0), _key3 = 1; _key3 < _len3; _key3++) {
      args[_key3 - 1] = arguments[_key3];
    }
    (this.domListeners[event.type] || []).forEach((_ref) => {
      let {
        node,
        handler
      } = _ref;
      if (event.target === node || node.contains(event.target)) {
        handler(event, ...args);
      }
    });
  }
  listenDOM(eventName, node, handler) {
    if (!this.domListeners[eventName]) {
      this.domListeners[eventName] = [];
    }
    this.domListeners[eventName].push({
      node,
      handler
    });
  }
};
var emitter_default = Emitter;

// node_modules/quill/core/selection.js
var debug3 = logger_default("quill:selection");
var Range = class {
  constructor(index) {
    let length = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : 0;
    this.index = index;
    this.length = length;
  }
};
var Selection = class {
  constructor(scroll, emitter) {
    this.emitter = emitter;
    this.scroll = scroll;
    this.composing = false;
    this.mouseDown = false;
    this.root = this.scroll.domNode;
    this.cursor = this.scroll.create("cursor", this);
    this.savedRange = new Range(0, 0);
    this.lastRange = this.savedRange;
    this.lastNative = null;
    this.handleComposition();
    this.handleDragging();
    this.emitter.listenDOM("selectionchange", document, () => {
      if (!this.mouseDown && !this.composing) {
        setTimeout(this.update.bind(this, emitter_default.sources.USER), 1);
      }
    });
    this.emitter.on(emitter_default.events.SCROLL_BEFORE_UPDATE, () => {
      if (!this.hasFocus()) return;
      const native = this.getNativeRange();
      if (native == null) return;
      if (native.start.node === this.cursor.textNode) return;
      this.emitter.once(emitter_default.events.SCROLL_UPDATE, (source, mutations) => {
        try {
          if (this.root.contains(native.start.node) && this.root.contains(native.end.node)) {
            this.setNativeRange(native.start.node, native.start.offset, native.end.node, native.end.offset);
          }
          const triggeredByTyping = mutations.some((mutation) => mutation.type === "characterData" || mutation.type === "childList" || mutation.type === "attributes" && mutation.target === this.root);
          this.update(triggeredByTyping ? emitter_default.sources.SILENT : source);
        } catch (ignored) {
        }
      });
    });
    this.emitter.on(emitter_default.events.SCROLL_OPTIMIZE, (mutations, context) => {
      if (context.range) {
        const {
          startNode,
          startOffset,
          endNode,
          endOffset
        } = context.range;
        this.setNativeRange(startNode, startOffset, endNode, endOffset);
        this.update(emitter_default.sources.SILENT);
      }
    });
    this.update(emitter_default.sources.SILENT);
  }
  handleComposition() {
    this.emitter.on(emitter_default.events.COMPOSITION_BEFORE_START, () => {
      this.composing = true;
    });
    this.emitter.on(emitter_default.events.COMPOSITION_END, () => {
      this.composing = false;
      if (this.cursor.parent) {
        const range2 = this.cursor.restore();
        if (!range2) return;
        setTimeout(() => {
          this.setNativeRange(range2.startNode, range2.startOffset, range2.endNode, range2.endOffset);
        }, 1);
      }
    });
  }
  handleDragging() {
    this.emitter.listenDOM("mousedown", document.body, () => {
      this.mouseDown = true;
    });
    this.emitter.listenDOM("mouseup", document.body, () => {
      this.mouseDown = false;
      this.update(emitter_default.sources.USER);
    });
  }
  focus() {
    if (this.hasFocus()) return;
    this.root.focus({
      preventScroll: true
    });
    this.setRange(this.savedRange);
  }
  format(format, value) {
    this.scroll.update();
    const nativeRange = this.getNativeRange();
    if (nativeRange == null || !nativeRange.native.collapsed || this.scroll.query(format, Scope.BLOCK)) return;
    if (nativeRange.start.node !== this.cursor.textNode) {
      const blot = this.scroll.find(nativeRange.start.node, false);
      if (blot == null) return;
      if (blot instanceof LeafBlot$1) {
        const after2 = blot.split(nativeRange.start.offset);
        blot.parent.insertBefore(this.cursor, after2);
      } else {
        blot.insertBefore(this.cursor, nativeRange.start.node);
      }
      this.cursor.attach();
    }
    this.cursor.format(format, value);
    this.scroll.optimize();
    this.setNativeRange(this.cursor.textNode, this.cursor.textNode.data.length);
    this.update();
  }
  getBounds(index) {
    let length = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : 0;
    const scrollLength = this.scroll.length();
    index = Math.min(index, scrollLength - 1);
    length = Math.min(index + length, scrollLength - 1) - index;
    let node;
    let [leaf, offset] = this.scroll.leaf(index);
    if (leaf == null) return null;
    if (length > 0 && offset === leaf.length()) {
      const [next] = this.scroll.leaf(index + 1);
      if (next) {
        const [line] = this.scroll.line(index);
        const [nextLine] = this.scroll.line(index + 1);
        if (line === nextLine) {
          leaf = next;
          offset = 0;
        }
      }
    }
    [node, offset] = leaf.position(offset, true);
    const range2 = document.createRange();
    if (length > 0) {
      range2.setStart(node, offset);
      [leaf, offset] = this.scroll.leaf(index + length);
      if (leaf == null) return null;
      [node, offset] = leaf.position(offset, true);
      range2.setEnd(node, offset);
      return range2.getBoundingClientRect();
    }
    let side = "left";
    let rect;
    if (node instanceof Text) {
      if (!node.data.length) {
        return null;
      }
      if (offset < node.data.length) {
        range2.setStart(node, offset);
        range2.setEnd(node, offset + 1);
      } else {
        range2.setStart(node, offset - 1);
        range2.setEnd(node, offset);
        side = "right";
      }
      rect = range2.getBoundingClientRect();
    } else {
      if (!(leaf.domNode instanceof Element)) return null;
      rect = leaf.domNode.getBoundingClientRect();
      if (offset > 0) side = "right";
    }
    return {
      bottom: rect.top + rect.height,
      height: rect.height,
      left: rect[side],
      right: rect[side],
      top: rect.top,
      width: 0
    };
  }
  getNativeRange() {
    const selection = document.getSelection();
    if (selection == null || selection.rangeCount <= 0) return null;
    const nativeRange = selection.getRangeAt(0);
    if (nativeRange == null) return null;
    const range2 = this.normalizeNative(nativeRange);
    debug3.info("getNativeRange", range2);
    return range2;
  }
  getRange() {
    const root2 = this.scroll.domNode;
    if ("isConnected" in root2 && !root2.isConnected) {
      return [null, null];
    }
    const normalized = this.getNativeRange();
    if (normalized == null) return [null, null];
    const range2 = this.normalizedToRange(normalized);
    return [range2, normalized];
  }
  hasFocus() {
    return document.activeElement === this.root || document.activeElement != null && contains(this.root, document.activeElement);
  }
  normalizedToRange(range2) {
    const positions = [[range2.start.node, range2.start.offset]];
    if (!range2.native.collapsed) {
      positions.push([range2.end.node, range2.end.offset]);
    }
    const indexes = positions.map((position) => {
      const [node, offset] = position;
      const blot = this.scroll.find(node, true);
      const index = blot.offset(this.scroll);
      if (offset === 0) {
        return index;
      }
      if (blot instanceof LeafBlot$1) {
        return index + blot.index(node, offset);
      }
      return index + blot.length();
    });
    const end = Math.min(Math.max(...indexes), this.scroll.length() - 1);
    const start = Math.min(end, ...indexes);
    return new Range(start, end - start);
  }
  normalizeNative(nativeRange) {
    if (!contains(this.root, nativeRange.startContainer) || !nativeRange.collapsed && !contains(this.root, nativeRange.endContainer)) {
      return null;
    }
    const range2 = {
      start: {
        node: nativeRange.startContainer,
        offset: nativeRange.startOffset
      },
      end: {
        node: nativeRange.endContainer,
        offset: nativeRange.endOffset
      },
      native: nativeRange
    };
    [range2.start, range2.end].forEach((position) => {
      let {
        node,
        offset
      } = position;
      while (!(node instanceof Text) && node.childNodes.length > 0) {
        if (node.childNodes.length > offset) {
          node = node.childNodes[offset];
          offset = 0;
        } else if (node.childNodes.length === offset) {
          node = node.lastChild;
          if (node instanceof Text) {
            offset = node.data.length;
          } else if (node.childNodes.length > 0) {
            offset = node.childNodes.length;
          } else {
            offset = node.childNodes.length + 1;
          }
        } else {
          break;
        }
      }
      position.node = node;
      position.offset = offset;
    });
    return range2;
  }
  rangeToNative(range2) {
    const scrollLength = this.scroll.length();
    const getPosition = (index, inclusive) => {
      index = Math.min(scrollLength - 1, index);
      const [leaf, leafOffset] = this.scroll.leaf(index);
      return leaf ? leaf.position(leafOffset, inclusive) : [null, -1];
    };
    return [...getPosition(range2.index, false), ...getPosition(range2.index + range2.length, true)];
  }
  setNativeRange(startNode, startOffset) {
    let endNode = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : startNode;
    let endOffset = arguments.length > 3 && arguments[3] !== void 0 ? arguments[3] : startOffset;
    let force = arguments.length > 4 && arguments[4] !== void 0 ? arguments[4] : false;
    debug3.info("setNativeRange", startNode, startOffset, endNode, endOffset);
    if (startNode != null && (this.root.parentNode == null || startNode.parentNode == null || // @ts-expect-error Fix me later
    endNode.parentNode == null)) {
      return;
    }
    const selection = document.getSelection();
    if (selection == null) return;
    if (startNode != null) {
      if (!this.hasFocus()) this.root.focus({
        preventScroll: true
      });
      const {
        native
      } = this.getNativeRange() || {};
      if (native == null || force || startNode !== native.startContainer || startOffset !== native.startOffset || endNode !== native.endContainer || endOffset !== native.endOffset) {
        if (startNode instanceof Element && startNode.tagName === "BR") {
          startOffset = Array.from(startNode.parentNode.childNodes).indexOf(startNode);
          startNode = startNode.parentNode;
        }
        if (endNode instanceof Element && endNode.tagName === "BR") {
          endOffset = Array.from(endNode.parentNode.childNodes).indexOf(endNode);
          endNode = endNode.parentNode;
        }
        const range2 = document.createRange();
        range2.setStart(startNode, startOffset);
        range2.setEnd(endNode, endOffset);
        selection.removeAllRanges();
        selection.addRange(range2);
      }
    } else {
      selection.removeAllRanges();
      this.root.blur();
    }
  }
  setRange(range2) {
    let force = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : false;
    let source = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : emitter_default.sources.API;
    if (typeof force === "string") {
      source = force;
      force = false;
    }
    debug3.info("setRange", range2);
    if (range2 != null) {
      const args = this.rangeToNative(range2);
      this.setNativeRange(...args, force);
    } else {
      this.setNativeRange(null);
    }
    this.update(source);
  }
  update() {
    let source = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : emitter_default.sources.USER;
    const oldRange = this.lastRange;
    const [lastRange, nativeRange] = this.getRange();
    this.lastRange = lastRange;
    this.lastNative = nativeRange;
    if (this.lastRange != null) {
      this.savedRange = this.lastRange;
    }
    if (!isEqual_default(oldRange, this.lastRange)) {
      if (!this.composing && nativeRange != null && nativeRange.native.collapsed && nativeRange.start.node !== this.cursor.textNode) {
        const range2 = this.cursor.restore();
        if (range2) {
          this.setNativeRange(range2.startNode, range2.startOffset, range2.endNode, range2.endOffset);
        }
      }
      const args = [emitter_default.events.SELECTION_CHANGE, cloneDeep_default(this.lastRange), cloneDeep_default(oldRange), source];
      this.emitter.emit(emitter_default.events.EDITOR_CHANGE, ...args);
      if (source !== emitter_default.sources.SILENT) {
        this.emitter.emit(...args);
      }
    }
  }
};
function contains(parent2, descendant) {
  try {
    descendant.parentNode;
  } catch (e) {
    return false;
  }
  return parent2.contains(descendant);
}
var selection_default = Selection;

// node_modules/quill/core/editor.js
var ASCII = /^[ -~]*$/;
var Editor = class {
  constructor(scroll) {
    this.scroll = scroll;
    this.delta = this.getDelta();
  }
  applyDelta(delta) {
    this.scroll.update();
    let scrollLength = this.scroll.length();
    this.scroll.batchStart();
    const normalizedDelta = normalizeDelta(delta);
    const deleteDelta = new import_quill_delta2.default();
    const normalizedOps = splitOpLines(normalizedDelta.ops.slice());
    normalizedOps.reduce((index, op) => {
      const length = import_quill_delta2.Op.length(op);
      let attributes = op.attributes || {};
      let isImplicitNewlinePrepended = false;
      let isImplicitNewlineAppended = false;
      if (op.insert != null) {
        deleteDelta.retain(length);
        if (typeof op.insert === "string") {
          const text = op.insert;
          isImplicitNewlineAppended = !text.endsWith("\n") && (scrollLength <= index || !!this.scroll.descendant(BlockEmbed, index)[0]);
          this.scroll.insertAt(index, text);
          const [line, offset] = this.scroll.line(index);
          let formats = merge_default({}, bubbleFormats(line));
          if (line instanceof Block) {
            const [leaf] = line.descendant(LeafBlot$1, offset);
            if (leaf) {
              formats = merge_default(formats, bubbleFormats(leaf));
            }
          }
          attributes = import_quill_delta2.AttributeMap.diff(formats, attributes) || {};
        } else if (typeof op.insert === "object") {
          const key = Object.keys(op.insert)[0];
          if (key == null) return index;
          const isInlineEmbed = this.scroll.query(key, Scope.INLINE) != null;
          if (isInlineEmbed) {
            if (scrollLength <= index || !!this.scroll.descendant(BlockEmbed, index)[0]) {
              isImplicitNewlineAppended = true;
            }
          } else if (index > 0) {
            const [leaf, offset] = this.scroll.descendant(LeafBlot$1, index - 1);
            if (leaf instanceof Text2) {
              const text = leaf.value();
              if (text[offset] !== "\n") {
                isImplicitNewlinePrepended = true;
              }
            } else if (leaf instanceof EmbedBlot$1 && leaf.statics.scope === Scope.INLINE_BLOT) {
              isImplicitNewlinePrepended = true;
            }
          }
          this.scroll.insertAt(index, key, op.insert[key]);
          if (isInlineEmbed) {
            const [leaf] = this.scroll.descendant(LeafBlot$1, index);
            if (leaf) {
              const formats = merge_default({}, bubbleFormats(leaf));
              attributes = import_quill_delta2.AttributeMap.diff(formats, attributes) || {};
            }
          }
        }
        scrollLength += length;
      } else {
        deleteDelta.push(op);
        if (op.retain !== null && typeof op.retain === "object") {
          const key = Object.keys(op.retain)[0];
          if (key == null) return index;
          this.scroll.updateEmbedAt(index, key, op.retain[key]);
        }
      }
      Object.keys(attributes).forEach((name) => {
        this.scroll.formatAt(index, length, name, attributes[name]);
      });
      const prependedLength = isImplicitNewlinePrepended ? 1 : 0;
      const addedLength = isImplicitNewlineAppended ? 1 : 0;
      scrollLength += prependedLength + addedLength;
      deleteDelta.retain(prependedLength);
      deleteDelta.delete(addedLength);
      return index + length + prependedLength + addedLength;
    }, 0);
    deleteDelta.reduce((index, op) => {
      if (typeof op.delete === "number") {
        this.scroll.deleteAt(index, op.delete);
        return index;
      }
      return index + import_quill_delta2.Op.length(op);
    }, 0);
    this.scroll.batchEnd();
    this.scroll.optimize();
    return this.update(normalizedDelta);
  }
  deleteText(index, length) {
    this.scroll.deleteAt(index, length);
    return this.update(new import_quill_delta2.default().retain(index).delete(length));
  }
  formatLine(index, length) {
    let formats = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : {};
    this.scroll.update();
    Object.keys(formats).forEach((format) => {
      this.scroll.lines(index, Math.max(length, 1)).forEach((line) => {
        line.format(format, formats[format]);
      });
    });
    this.scroll.optimize();
    const delta = new import_quill_delta2.default().retain(index).retain(length, cloneDeep_default(formats));
    return this.update(delta);
  }
  formatText(index, length) {
    let formats = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : {};
    Object.keys(formats).forEach((format) => {
      this.scroll.formatAt(index, length, format, formats[format]);
    });
    const delta = new import_quill_delta2.default().retain(index).retain(length, cloneDeep_default(formats));
    return this.update(delta);
  }
  getContents(index, length) {
    return this.delta.slice(index, index + length);
  }
  getDelta() {
    return this.scroll.lines().reduce((delta, line) => {
      return delta.concat(line.delta());
    }, new import_quill_delta2.default());
  }
  getFormat(index) {
    let length = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : 0;
    let lines = [];
    let leaves = [];
    if (length === 0) {
      this.scroll.path(index).forEach((path) => {
        const [blot] = path;
        if (blot instanceof Block) {
          lines.push(blot);
        } else if (blot instanceof LeafBlot$1) {
          leaves.push(blot);
        }
      });
    } else {
      lines = this.scroll.lines(index, length);
      leaves = this.scroll.descendants(LeafBlot$1, index, length);
    }
    const [lineFormats, leafFormats] = [lines, leaves].map((blots) => {
      const blot = blots.shift();
      if (blot == null) return {};
      let formats = bubbleFormats(blot);
      while (Object.keys(formats).length > 0) {
        const blot2 = blots.shift();
        if (blot2 == null) return formats;
        formats = combineFormats(bubbleFormats(blot2), formats);
      }
      return formats;
    });
    return __spreadValues(__spreadValues({}, lineFormats), leafFormats);
  }
  getHTML(index, length) {
    const [line, lineOffset] = this.scroll.line(index);
    if (line) {
      const lineLength = line.length();
      const isWithinLine = line.length() >= lineOffset + length;
      if (isWithinLine && !(lineOffset === 0 && length === lineLength)) {
        return convertHTML(line, lineOffset, length, true);
      }
      return convertHTML(this.scroll, index, length, true);
    }
    return "";
  }
  getText(index, length) {
    return this.getContents(index, length).filter((op) => typeof op.insert === "string").map((op) => op.insert).join("");
  }
  insertContents(index, contents) {
    const normalizedDelta = normalizeDelta(contents);
    const change = new import_quill_delta2.default().retain(index).concat(normalizedDelta);
    this.scroll.insertContents(index, normalizedDelta);
    return this.update(change);
  }
  insertEmbed(index, embed, value) {
    this.scroll.insertAt(index, embed, value);
    return this.update(new import_quill_delta2.default().retain(index).insert({
      [embed]: value
    }));
  }
  insertText(index, text) {
    let formats = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : {};
    text = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    this.scroll.insertAt(index, text);
    Object.keys(formats).forEach((format) => {
      this.scroll.formatAt(index, text.length, format, formats[format]);
    });
    return this.update(new import_quill_delta2.default().retain(index).insert(text, cloneDeep_default(formats)));
  }
  isBlank() {
    if (this.scroll.children.length === 0) return true;
    if (this.scroll.children.length > 1) return false;
    const blot = this.scroll.children.head;
    if (blot?.statics.blotName !== Block.blotName) return false;
    const block = blot;
    if (block.children.length > 1) return false;
    return block.children.head instanceof break_default;
  }
  removeFormat(index, length) {
    const text = this.getText(index, length);
    const [line, offset] = this.scroll.line(index + length);
    let suffixLength = 0;
    let suffix = new import_quill_delta2.default();
    if (line != null) {
      suffixLength = line.length() - offset;
      suffix = line.delta().slice(offset, offset + suffixLength - 1).insert("\n");
    }
    const contents = this.getContents(index, length + suffixLength);
    const diff = contents.diff(new import_quill_delta2.default().insert(text).concat(suffix));
    const delta = new import_quill_delta2.default().retain(index).concat(diff);
    return this.applyDelta(delta);
  }
  update(change) {
    let mutations = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : [];
    let selectionInfo = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : void 0;
    const oldDelta = this.delta;
    if (mutations.length === 1 && mutations[0].type === "characterData" && // @ts-expect-error Fix me later
    mutations[0].target.data.match(ASCII) && this.scroll.find(mutations[0].target)) {
      const textBlot = this.scroll.find(mutations[0].target);
      const formats = bubbleFormats(textBlot);
      const index = textBlot.offset(this.scroll);
      const oldValue = mutations[0].oldValue.replace(cursor_default.CONTENTS, "");
      const oldText = new import_quill_delta2.default().insert(oldValue);
      const newText = new import_quill_delta2.default().insert(textBlot.value());
      const relativeSelectionInfo = selectionInfo && {
        oldRange: shiftRange(selectionInfo.oldRange, -index),
        newRange: shiftRange(selectionInfo.newRange, -index)
      };
      const diffDelta = new import_quill_delta2.default().retain(index).concat(oldText.diff(newText, relativeSelectionInfo));
      change = diffDelta.reduce((delta, op) => {
        if (op.insert) {
          return delta.insert(op.insert, formats);
        }
        return delta.push(op);
      }, new import_quill_delta2.default());
      this.delta = oldDelta.compose(change);
    } else {
      this.delta = this.getDelta();
      if (!change || !isEqual_default(oldDelta.compose(change), this.delta)) {
        change = oldDelta.diff(this.delta, selectionInfo);
      }
    }
    return change;
  }
};
function convertListHTML(items, lastIndent, types) {
  if (items.length === 0) {
    const [endTag2] = getListType(types.pop());
    if (lastIndent <= 0) {
      return `</li></${endTag2}>`;
    }
    return `</li></${endTag2}>${convertListHTML([], lastIndent - 1, types)}`;
  }
  const [{
    child,
    offset,
    length,
    indent,
    type
  }, ...rest2] = items;
  const [tag, attribute] = getListType(type);
  if (indent > lastIndent) {
    types.push(type);
    if (indent === lastIndent + 1) {
      return `<${tag}><li${attribute}>${convertHTML(child, offset, length)}${convertListHTML(rest2, indent, types)}`;
    }
    return `<${tag}><li>${convertListHTML(items, lastIndent + 1, types)}`;
  }
  const previousType = types[types.length - 1];
  if (indent === lastIndent && type === previousType) {
    return `</li><li${attribute}>${convertHTML(child, offset, length)}${convertListHTML(rest2, indent, types)}`;
  }
  const [endTag] = getListType(types.pop());
  return `</li></${endTag}>${convertListHTML(items, lastIndent - 1, types)}`;
}
function convertHTML(blot, index, length) {
  let isRoot = arguments.length > 3 && arguments[3] !== void 0 ? arguments[3] : false;
  if ("html" in blot && typeof blot.html === "function") {
    return blot.html(index, length);
  }
  if (blot instanceof Text2) {
    const escapedText = escapeText(blot.value().slice(index, index + length));
    return escapedText.replaceAll(" ", "&nbsp;");
  }
  if (blot instanceof ParentBlot$1) {
    if (blot.statics.blotName === "list-container") {
      const items = [];
      blot.children.forEachAt(index, length, (child, offset, childLength) => {
        const formats = "formats" in child && typeof child.formats === "function" ? child.formats() : {};
        items.push({
          child,
          offset,
          length: childLength,
          indent: formats.indent || 0,
          type: formats.list
        });
      });
      return convertListHTML(items, -1, []);
    }
    const parts = [];
    blot.children.forEachAt(index, length, (child, offset, childLength) => {
      parts.push(convertHTML(child, offset, childLength));
    });
    if (isRoot || blot.statics.blotName === "list") {
      return parts.join("");
    }
    const {
      outerHTML,
      innerHTML
    } = blot.domNode;
    const [start, end] = outerHTML.split(`>${innerHTML}<`);
    if (start === "<table") {
      return `<table style="border: 1px solid #000;">${parts.join("")}<${end}`;
    }
    return `${start}>${parts.join("")}<${end}`;
  }
  return blot.domNode instanceof Element ? blot.domNode.outerHTML : "";
}
function combineFormats(formats, combined) {
  return Object.keys(combined).reduce((merged, name) => {
    if (formats[name] == null) return merged;
    const combinedValue = combined[name];
    if (combinedValue === formats[name]) {
      merged[name] = combinedValue;
    } else if (Array.isArray(combinedValue)) {
      if (combinedValue.indexOf(formats[name]) < 0) {
        merged[name] = combinedValue.concat([formats[name]]);
      } else {
        merged[name] = combinedValue;
      }
    } else {
      merged[name] = [combinedValue, formats[name]];
    }
    return merged;
  }, {});
}
function getListType(type) {
  const tag = type === "ordered" ? "ol" : "ul";
  switch (type) {
    case "checked":
      return [tag, ' data-list="checked"'];
    case "unchecked":
      return [tag, ' data-list="unchecked"'];
    default:
      return [tag, ""];
  }
}
function normalizeDelta(delta) {
  return delta.reduce((normalizedDelta, op) => {
    if (typeof op.insert === "string") {
      const text = op.insert.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
      return normalizedDelta.insert(text, op.attributes);
    }
    return normalizedDelta.push(op);
  }, new import_quill_delta2.default());
}
function shiftRange(_ref, amount) {
  let {
    index,
    length
  } = _ref;
  return new Range(index + amount, length);
}
function splitOpLines(ops) {
  const split2 = [];
  ops.forEach((op) => {
    if (typeof op.insert === "string") {
      const lines = op.insert.split("\n");
      lines.forEach((line, index) => {
        if (index) split2.push({
          insert: "\n",
          attributes: op.attributes
        });
        if (line) split2.push({
          insert: line,
          attributes: op.attributes
        });
      });
    } else {
      split2.push(op);
    }
  });
  return split2;
}
var editor_default = Editor;

// node_modules/quill/core/module.js
var Module = class {
  static DEFAULTS = {};
  constructor(quill) {
    let options = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : {};
    this.quill = quill;
    this.options = options;
  }
};
var module_default = Module;

// node_modules/quill/blots/embed.js
var GUARD_TEXT = "\uFEFF";
var Embed = class extends EmbedBlot$1 {
  constructor(scroll, node) {
    super(scroll, node);
    this.contentNode = document.createElement("span");
    this.contentNode.setAttribute("contenteditable", "false");
    Array.from(this.domNode.childNodes).forEach((childNode) => {
      this.contentNode.appendChild(childNode);
    });
    this.leftGuard = document.createTextNode(GUARD_TEXT);
    this.rightGuard = document.createTextNode(GUARD_TEXT);
    this.domNode.appendChild(this.leftGuard);
    this.domNode.appendChild(this.contentNode);
    this.domNode.appendChild(this.rightGuard);
  }
  index(node, offset) {
    if (node === this.leftGuard) return 0;
    if (node === this.rightGuard) return 1;
    return super.index(node, offset);
  }
  restore(node) {
    let range2 = null;
    let textNode;
    const text = node.data.split(GUARD_TEXT).join("");
    if (node === this.leftGuard) {
      if (this.prev instanceof Text2) {
        const prevLength = this.prev.length();
        this.prev.insertAt(prevLength, text);
        range2 = {
          startNode: this.prev.domNode,
          startOffset: prevLength + text.length
        };
      } else {
        textNode = document.createTextNode(text);
        this.parent.insertBefore(this.scroll.create(textNode), this);
        range2 = {
          startNode: textNode,
          startOffset: text.length
        };
      }
    } else if (node === this.rightGuard) {
      if (this.next instanceof Text2) {
        this.next.insertAt(0, text);
        range2 = {
          startNode: this.next.domNode,
          startOffset: text.length
        };
      } else {
        textNode = document.createTextNode(text);
        this.parent.insertBefore(this.scroll.create(textNode), this.next);
        range2 = {
          startNode: textNode,
          startOffset: text.length
        };
      }
    }
    node.data = GUARD_TEXT;
    return range2;
  }
  update(mutations, context) {
    mutations.forEach((mutation) => {
      if (mutation.type === "characterData" && (mutation.target === this.leftGuard || mutation.target === this.rightGuard)) {
        const range2 = this.restore(mutation.target);
        if (range2) context.range = range2;
      }
    });
  }
};
var embed_default = Embed;

// node_modules/quill/core/composition.js
var Composition = class {
  isComposing = false;
  constructor(scroll, emitter) {
    this.scroll = scroll;
    this.emitter = emitter;
    this.setupListeners();
  }
  setupListeners() {
    this.scroll.domNode.addEventListener("compositionstart", (event) => {
      if (!this.isComposing) {
        this.handleCompositionStart(event);
      }
    });
    this.scroll.domNode.addEventListener("compositionend", (event) => {
      if (this.isComposing) {
        queueMicrotask(() => {
          this.handleCompositionEnd(event);
        });
      }
    });
  }
  handleCompositionStart(event) {
    const blot = event.target instanceof Node ? this.scroll.find(event.target, true) : null;
    if (blot && !(blot instanceof embed_default)) {
      this.emitter.emit(emitter_default.events.COMPOSITION_BEFORE_START, event);
      this.scroll.batchStart();
      this.emitter.emit(emitter_default.events.COMPOSITION_START, event);
      this.isComposing = true;
    }
  }
  handleCompositionEnd(event) {
    this.emitter.emit(emitter_default.events.COMPOSITION_BEFORE_END, event);
    this.scroll.batchEnd();
    this.emitter.emit(emitter_default.events.COMPOSITION_END, event);
    this.isComposing = false;
  }
};
var composition_default = Composition;

// node_modules/quill/core/theme.js
var Theme = class _Theme {
  static DEFAULTS = {
    modules: {}
  };
  static themes = {
    default: _Theme
  };
  modules = {};
  constructor(quill, options) {
    this.quill = quill;
    this.options = options;
  }
  init() {
    Object.keys(this.options.modules).forEach((name) => {
      if (this.modules[name] == null) {
        this.addModule(name);
      }
    });
  }
  addModule(name) {
    const ModuleClass = this.quill.constructor.import(`modules/${name}`);
    this.modules[name] = new ModuleClass(this.quill, this.options.modules[name] || {});
    return this.modules[name];
  }
};
var theme_default = Theme;

// node_modules/quill/core/utils/scrollRectIntoView.js
var getParentElement = (element) => element.parentElement || element.getRootNode().host || null;
var getElementRect = (element) => {
  const rect = element.getBoundingClientRect();
  const scaleX = "offsetWidth" in element && Math.abs(rect.width) / element.offsetWidth || 1;
  const scaleY = "offsetHeight" in element && Math.abs(rect.height) / element.offsetHeight || 1;
  return {
    top: rect.top,
    right: rect.left + element.clientWidth * scaleX,
    bottom: rect.top + element.clientHeight * scaleY,
    left: rect.left
  };
};
var paddingValueToInt = (value) => {
  const number = parseInt(value, 10);
  return Number.isNaN(number) ? 0 : number;
};
var getScrollDistance = (targetStart, targetEnd, scrollStart, scrollEnd, scrollPaddingStart, scrollPaddingEnd) => {
  if (targetStart < scrollStart && targetEnd > scrollEnd) {
    return 0;
  }
  if (targetStart < scrollStart) {
    return -(scrollStart - targetStart + scrollPaddingStart);
  }
  if (targetEnd > scrollEnd) {
    return targetEnd - targetStart > scrollEnd - scrollStart ? targetStart + scrollPaddingStart - scrollStart : targetEnd - scrollEnd + scrollPaddingEnd;
  }
  return 0;
};
var scrollRectIntoView = (root2, targetRect) => {
  const document2 = root2.ownerDocument;
  let rect = targetRect;
  let current = root2;
  while (current) {
    const isDocumentBody = current === document2.body;
    const bounding = isDocumentBody ? {
      top: 0,
      right: window.visualViewport?.width ?? document2.documentElement.clientWidth,
      bottom: window.visualViewport?.height ?? document2.documentElement.clientHeight,
      left: 0
    } : getElementRect(current);
    const style = getComputedStyle(current);
    const scrollDistanceX = getScrollDistance(rect.left, rect.right, bounding.left, bounding.right, paddingValueToInt(style.scrollPaddingLeft), paddingValueToInt(style.scrollPaddingRight));
    const scrollDistanceY = getScrollDistance(rect.top, rect.bottom, bounding.top, bounding.bottom, paddingValueToInt(style.scrollPaddingTop), paddingValueToInt(style.scrollPaddingBottom));
    if (scrollDistanceX || scrollDistanceY) {
      if (isDocumentBody) {
        document2.defaultView?.scrollBy(scrollDistanceX, scrollDistanceY);
      } else {
        const {
          scrollLeft,
          scrollTop
        } = current;
        if (scrollDistanceY) {
          current.scrollTop += scrollDistanceY;
        }
        if (scrollDistanceX) {
          current.scrollLeft += scrollDistanceX;
        }
        const scrolledLeft = current.scrollLeft - scrollLeft;
        const scrolledTop = current.scrollTop - scrollTop;
        rect = {
          left: rect.left - scrolledLeft,
          top: rect.top - scrolledTop,
          right: rect.right - scrolledLeft,
          bottom: rect.bottom - scrolledTop
        };
      }
    }
    current = isDocumentBody || style.position === "fixed" ? null : getParentElement(current);
  }
};
var scrollRectIntoView_default = scrollRectIntoView;

// node_modules/quill/core/utils/createRegistryWithFormats.js
var MAX_REGISTER_ITERATIONS = 100;
var CORE_FORMATS = ["block", "break", "cursor", "inline", "scroll", "text"];
var createRegistryWithFormats = (formats, sourceRegistry, debug8) => {
  const registry = new Registry();
  CORE_FORMATS.forEach((name) => {
    const coreBlot = sourceRegistry.query(name);
    if (coreBlot) registry.register(coreBlot);
  });
  formats.forEach((name) => {
    let format = sourceRegistry.query(name);
    if (!format) {
      debug8.error(`Cannot register "${name}" specified in "formats" config. Are you sure it was registered?`);
    }
    let iterations = 0;
    while (format) {
      registry.register(format);
      format = "blotName" in format ? format.requiredContainer ?? null : null;
      iterations += 1;
      if (iterations > MAX_REGISTER_ITERATIONS) {
        debug8.error(`Cycle detected in registering blot requiredContainer: "${name}"`);
        break;
      }
    }
  });
  return registry;
};
var createRegistryWithFormats_default = createRegistryWithFormats;

// node_modules/quill/core/quill.js
var debug4 = logger_default("quill");
var globalRegistry = new Registry();
ParentBlot$1.uiClass = "ql-ui";
var Quill = class _Quill {
  static DEFAULTS = {
    bounds: null,
    modules: {
      clipboard: true,
      keyboard: true,
      history: true,
      uploader: true
    },
    placeholder: "",
    readOnly: false,
    registry: globalRegistry,
    theme: "default"
  };
  static events = emitter_default.events;
  static sources = emitter_default.sources;
  static version = false ? "dev" : "2.0.3";
  static imports = {
    delta: import_quill_delta3.default,
    parchment: parchment_exports,
    "core/module": module_default,
    "core/theme": theme_default
  };
  static debug(limit) {
    if (limit === true) {
      limit = "log";
    }
    logger_default.level(limit);
  }
  static find(node) {
    let bubble = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : false;
    return instances_default.get(node) || globalRegistry.find(node, bubble);
  }
  static import(name) {
    if (this.imports[name] == null) {
      debug4.error(`Cannot import ${name}. Are you sure it was registered?`);
    }
    return this.imports[name];
  }
  static register() {
    if (typeof (arguments.length <= 0 ? void 0 : arguments[0]) !== "string") {
      const target = arguments.length <= 0 ? void 0 : arguments[0];
      const overwrite = !!(arguments.length <= 1 ? void 0 : arguments[1]);
      const name = "attrName" in target ? target.attrName : target.blotName;
      if (typeof name === "string") {
        this.register(`formats/${name}`, target, overwrite);
      } else {
        Object.keys(target).forEach((key) => {
          this.register(key, target[key], overwrite);
        });
      }
    } else {
      const path = arguments.length <= 0 ? void 0 : arguments[0];
      const target = arguments.length <= 1 ? void 0 : arguments[1];
      const overwrite = !!(arguments.length <= 2 ? void 0 : arguments[2]);
      if (this.imports[path] != null && !overwrite) {
        debug4.warn(`Overwriting ${path} with`, target);
      }
      this.imports[path] = target;
      if ((path.startsWith("blots/") || path.startsWith("formats/")) && target && typeof target !== "boolean" && target.blotName !== "abstract") {
        globalRegistry.register(target);
      }
      if (typeof target.register === "function") {
        target.register(globalRegistry);
      }
    }
  }
  constructor(container) {
    let options = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : {};
    this.options = expandConfig(container, options);
    this.container = this.options.container;
    if (this.container == null) {
      debug4.error("Invalid Quill container", container);
      return;
    }
    if (this.options.debug) {
      _Quill.debug(this.options.debug);
    }
    const html = this.container.innerHTML.trim();
    this.container.classList.add("ql-container");
    this.container.innerHTML = "";
    instances_default.set(this.container, this);
    this.root = this.addContainer("ql-editor");
    this.root.classList.add("ql-blank");
    this.emitter = new emitter_default();
    const scrollBlotName = ScrollBlot$1.blotName;
    const ScrollBlot2 = this.options.registry.query(scrollBlotName);
    if (!ScrollBlot2 || !("blotName" in ScrollBlot2)) {
      throw new Error(`Cannot initialize Quill without "${scrollBlotName}" blot`);
    }
    this.scroll = new ScrollBlot2(this.options.registry, this.root, {
      emitter: this.emitter
    });
    this.editor = new editor_default(this.scroll);
    this.selection = new selection_default(this.scroll, this.emitter);
    this.composition = new composition_default(this.scroll, this.emitter);
    this.theme = new this.options.theme(this, this.options);
    this.keyboard = this.theme.addModule("keyboard");
    this.clipboard = this.theme.addModule("clipboard");
    this.history = this.theme.addModule("history");
    this.uploader = this.theme.addModule("uploader");
    this.theme.addModule("input");
    this.theme.addModule("uiNode");
    this.theme.init();
    this.emitter.on(emitter_default.events.EDITOR_CHANGE, (type) => {
      if (type === emitter_default.events.TEXT_CHANGE) {
        this.root.classList.toggle("ql-blank", this.editor.isBlank());
      }
    });
    this.emitter.on(emitter_default.events.SCROLL_UPDATE, (source, mutations) => {
      const oldRange = this.selection.lastRange;
      const [newRange] = this.selection.getRange();
      const selectionInfo = oldRange && newRange ? {
        oldRange,
        newRange
      } : void 0;
      modify.call(this, () => this.editor.update(null, mutations, selectionInfo), source);
    });
    this.emitter.on(emitter_default.events.SCROLL_EMBED_UPDATE, (blot, delta) => {
      const oldRange = this.selection.lastRange;
      const [newRange] = this.selection.getRange();
      const selectionInfo = oldRange && newRange ? {
        oldRange,
        newRange
      } : void 0;
      modify.call(this, () => {
        const change = new import_quill_delta3.default().retain(blot.offset(this)).retain({
          [blot.statics.blotName]: delta
        });
        return this.editor.update(change, [], selectionInfo);
      }, _Quill.sources.USER);
    });
    if (html) {
      const contents = this.clipboard.convert({
        html: `${html}<p><br></p>`,
        text: "\n"
      });
      this.setContents(contents);
    }
    this.history.clear();
    if (this.options.placeholder) {
      this.root.setAttribute("data-placeholder", this.options.placeholder);
    }
    if (this.options.readOnly) {
      this.disable();
    }
    this.allowReadOnlyEdits = false;
  }
  addContainer(container) {
    let refNode = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : null;
    if (typeof container === "string") {
      const className = container;
      container = document.createElement("div");
      container.classList.add(className);
    }
    this.container.insertBefore(container, refNode);
    return container;
  }
  blur() {
    this.selection.setRange(null);
  }
  deleteText(index, length, source) {
    [index, length, , source] = overload(index, length, source);
    return modify.call(this, () => {
      return this.editor.deleteText(index, length);
    }, source, index, -1 * length);
  }
  disable() {
    this.enable(false);
  }
  editReadOnly(modifier) {
    this.allowReadOnlyEdits = true;
    const value = modifier();
    this.allowReadOnlyEdits = false;
    return value;
  }
  enable() {
    let enabled = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : true;
    this.scroll.enable(enabled);
    this.container.classList.toggle("ql-disabled", !enabled);
  }
  focus() {
    let options = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : {};
    this.selection.focus();
    if (!options.preventScroll) {
      this.scrollSelectionIntoView();
    }
  }
  format(name, value) {
    let source = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : emitter_default.sources.API;
    return modify.call(this, () => {
      const range2 = this.getSelection(true);
      let change = new import_quill_delta3.default();
      if (range2 == null) return change;
      if (this.scroll.query(name, Scope.BLOCK)) {
        change = this.editor.formatLine(range2.index, range2.length, {
          [name]: value
        });
      } else if (range2.length === 0) {
        this.selection.format(name, value);
        return change;
      } else {
        change = this.editor.formatText(range2.index, range2.length, {
          [name]: value
        });
      }
      this.setSelection(range2, emitter_default.sources.SILENT);
      return change;
    }, source);
  }
  formatLine(index, length, name, value, source) {
    let formats;
    [index, length, formats, source] = overload(
      index,
      length,
      // @ts-expect-error
      name,
      value,
      source
    );
    return modify.call(this, () => {
      return this.editor.formatLine(index, length, formats);
    }, source, index, 0);
  }
  formatText(index, length, name, value, source) {
    let formats;
    [index, length, formats, source] = overload(
      // @ts-expect-error
      index,
      length,
      name,
      value,
      source
    );
    return modify.call(this, () => {
      return this.editor.formatText(index, length, formats);
    }, source, index, 0);
  }
  getBounds(index) {
    let length = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : 0;
    let bounds = null;
    if (typeof index === "number") {
      bounds = this.selection.getBounds(index, length);
    } else {
      bounds = this.selection.getBounds(index.index, index.length);
    }
    if (!bounds) return null;
    const containerBounds = this.container.getBoundingClientRect();
    return {
      bottom: bounds.bottom - containerBounds.top,
      height: bounds.height,
      left: bounds.left - containerBounds.left,
      right: bounds.right - containerBounds.left,
      top: bounds.top - containerBounds.top,
      width: bounds.width
    };
  }
  getContents() {
    let index = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : 0;
    let length = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : this.getLength() - index;
    [index, length] = overload(index, length);
    return this.editor.getContents(index, length);
  }
  getFormat() {
    let index = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : this.getSelection(true);
    let length = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : 0;
    if (typeof index === "number") {
      return this.editor.getFormat(index, length);
    }
    return this.editor.getFormat(index.index, index.length);
  }
  getIndex(blot) {
    return blot.offset(this.scroll);
  }
  getLength() {
    return this.scroll.length();
  }
  getLeaf(index) {
    return this.scroll.leaf(index);
  }
  getLine(index) {
    return this.scroll.line(index);
  }
  getLines() {
    let index = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : 0;
    let length = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : Number.MAX_VALUE;
    if (typeof index !== "number") {
      return this.scroll.lines(index.index, index.length);
    }
    return this.scroll.lines(index, length);
  }
  getModule(name) {
    return this.theme.modules[name];
  }
  getSelection() {
    let focus = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : false;
    if (focus) this.focus();
    this.update();
    return this.selection.getRange()[0];
  }
  getSemanticHTML() {
    let index = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : 0;
    let length = arguments.length > 1 ? arguments[1] : void 0;
    if (typeof index === "number") {
      length = length ?? this.getLength() - index;
    }
    [index, length] = overload(index, length);
    return this.editor.getHTML(index, length);
  }
  getText() {
    let index = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : 0;
    let length = arguments.length > 1 ? arguments[1] : void 0;
    if (typeof index === "number") {
      length = length ?? this.getLength() - index;
    }
    [index, length] = overload(index, length);
    return this.editor.getText(index, length);
  }
  hasFocus() {
    return this.selection.hasFocus();
  }
  insertEmbed(index, embed, value) {
    let source = arguments.length > 3 && arguments[3] !== void 0 ? arguments[3] : _Quill.sources.API;
    return modify.call(this, () => {
      return this.editor.insertEmbed(index, embed, value);
    }, source, index);
  }
  insertText(index, text, name, value, source) {
    let formats;
    [index, , formats, source] = overload(index, 0, name, value, source);
    return modify.call(this, () => {
      return this.editor.insertText(index, text, formats);
    }, source, index, text.length);
  }
  isEnabled() {
    return this.scroll.isEnabled();
  }
  off() {
    return this.emitter.off(...arguments);
  }
  on() {
    return this.emitter.on(...arguments);
  }
  once() {
    return this.emitter.once(...arguments);
  }
  removeFormat(index, length, source) {
    [index, length, , source] = overload(index, length, source);
    return modify.call(this, () => {
      return this.editor.removeFormat(index, length);
    }, source, index);
  }
  scrollRectIntoView(rect) {
    scrollRectIntoView_default(this.root, rect);
  }
  /**
   * @deprecated Use Quill#scrollSelectionIntoView() instead.
   */
  scrollIntoView() {
    console.warn("Quill#scrollIntoView() has been deprecated and will be removed in the near future. Please use Quill#scrollSelectionIntoView() instead.");
    this.scrollSelectionIntoView();
  }
  /**
   * Scroll the current selection into the visible area.
   * If the selection is already visible, no scrolling will occur.
   */
  scrollSelectionIntoView() {
    const range2 = this.selection.lastRange;
    const bounds = range2 && this.selection.getBounds(range2.index, range2.length);
    if (bounds) {
      this.scrollRectIntoView(bounds);
    }
  }
  setContents(delta) {
    let source = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : emitter_default.sources.API;
    return modify.call(this, () => {
      delta = new import_quill_delta3.default(delta);
      const length = this.getLength();
      const delete1 = this.editor.deleteText(0, length);
      const applied = this.editor.insertContents(0, delta);
      const delete2 = this.editor.deleteText(this.getLength() - 1, 1);
      return delete1.compose(applied).compose(delete2);
    }, source);
  }
  setSelection(index, length, source) {
    if (index == null) {
      this.selection.setRange(null, length || _Quill.sources.API);
    } else {
      [index, length, , source] = overload(index, length, source);
      this.selection.setRange(new Range(Math.max(0, index), length), source);
      if (source !== emitter_default.sources.SILENT) {
        this.scrollSelectionIntoView();
      }
    }
  }
  setText(text) {
    let source = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : emitter_default.sources.API;
    const delta = new import_quill_delta3.default().insert(text);
    return this.setContents(delta, source);
  }
  update() {
    let source = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : emitter_default.sources.USER;
    const change = this.scroll.update(source);
    this.selection.update(source);
    return change;
  }
  updateContents(delta) {
    let source = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : emitter_default.sources.API;
    return modify.call(this, () => {
      delta = new import_quill_delta3.default(delta);
      return this.editor.applyDelta(delta);
    }, source, true);
  }
};
function resolveSelector(selector) {
  return typeof selector === "string" ? document.querySelector(selector) : selector;
}
function expandModuleConfig(config4) {
  return Object.entries(config4 ?? {}).reduce((expanded, _ref) => {
    let [key, value] = _ref;
    return __spreadProps(__spreadValues({}, expanded), {
      [key]: value === true ? {} : value
    });
  }, {});
}
function omitUndefinedValuesFromOptions(obj) {
  return Object.fromEntries(Object.entries(obj).filter((entry) => entry[1] !== void 0));
}
function expandConfig(containerOrSelector, options) {
  const container = resolveSelector(containerOrSelector);
  if (!container) {
    throw new Error("Invalid Quill container");
  }
  const shouldUseDefaultTheme = !options.theme || options.theme === Quill.DEFAULTS.theme;
  const theme = shouldUseDefaultTheme ? theme_default : Quill.import(`themes/${options.theme}`);
  if (!theme) {
    throw new Error(`Invalid theme ${options.theme}. Did you register it?`);
  }
  const _a = Quill.DEFAULTS, {
    modules: quillModuleDefaults
  } = _a, quillDefaults = __objRest(_a, [
    "modules"
  ]);
  const _b = theme.DEFAULTS, {
    modules: themeModuleDefaults
  } = _b, themeDefaults = __objRest(_b, [
    "modules"
  ]);
  let userModuleOptions = expandModuleConfig(options.modules);
  if (userModuleOptions != null && userModuleOptions.toolbar && userModuleOptions.toolbar.constructor !== Object) {
    userModuleOptions = __spreadProps(__spreadValues({}, userModuleOptions), {
      toolbar: {
        container: userModuleOptions.toolbar
      }
    });
  }
  const modules = merge_default({}, expandModuleConfig(quillModuleDefaults), expandModuleConfig(themeModuleDefaults), userModuleOptions);
  const config4 = __spreadValues(__spreadValues(__spreadValues({}, quillDefaults), omitUndefinedValuesFromOptions(themeDefaults)), omitUndefinedValuesFromOptions(options));
  let registry = options.registry;
  if (registry) {
    if (options.formats) {
      debug4.warn('Ignoring "formats" option because "registry" is specified');
    }
  } else {
    registry = options.formats ? createRegistryWithFormats_default(options.formats, config4.registry, debug4) : config4.registry;
  }
  return __spreadProps(__spreadValues({}, config4), {
    registry,
    container,
    theme,
    modules: Object.entries(modules).reduce((modulesWithDefaults, _ref2) => {
      let [name, value] = _ref2;
      if (!value) return modulesWithDefaults;
      const moduleClass = Quill.import(`modules/${name}`);
      if (moduleClass == null) {
        debug4.error(`Cannot load ${name} module. Are you sure you registered it?`);
        return modulesWithDefaults;
      }
      return __spreadProps(__spreadValues({}, modulesWithDefaults), {
        // @ts-expect-error
        [name]: merge_default({}, moduleClass.DEFAULTS || {}, value)
      });
    }, {}),
    bounds: resolveSelector(config4.bounds)
  });
}
function modify(modifier, source, index, shift) {
  if (!this.isEnabled() && source === emitter_default.sources.USER && !this.allowReadOnlyEdits) {
    return new import_quill_delta3.default();
  }
  let range2 = index == null ? null : this.getSelection();
  const oldDelta = this.editor.delta;
  const change = modifier();
  if (range2 != null) {
    if (index === true) {
      index = range2.index;
    }
    if (shift == null) {
      range2 = shiftRange2(range2, change, source);
    } else if (shift !== 0) {
      range2 = shiftRange2(range2, index, shift, source);
    }
    this.setSelection(range2, emitter_default.sources.SILENT);
  }
  if (change.length() > 0) {
    const args = [emitter_default.events.TEXT_CHANGE, change, oldDelta, source];
    this.emitter.emit(emitter_default.events.EDITOR_CHANGE, ...args);
    if (source !== emitter_default.sources.SILENT) {
      this.emitter.emit(...args);
    }
  }
  return change;
}
function overload(index, length, name, value, source) {
  let formats = {};
  if (typeof index.index === "number" && typeof index.length === "number") {
    if (typeof length !== "number") {
      source = value;
      value = name;
      name = length;
      length = index.length;
      index = index.index;
    } else {
      length = index.length;
      index = index.index;
    }
  } else if (typeof length !== "number") {
    source = value;
    value = name;
    name = length;
    length = 0;
  }
  if (typeof name === "object") {
    formats = name;
    source = value;
  } else if (typeof name === "string") {
    if (value != null) {
      formats[name] = value;
    } else {
      source = name;
    }
  }
  source = source || emitter_default.sources.API;
  return [index, length, formats, source];
}
function shiftRange2(range2, index, lengthOrSource, source) {
  const length = typeof lengthOrSource === "number" ? lengthOrSource : 0;
  if (range2 == null) return null;
  let start;
  let end;
  if (index && typeof index.transformPosition === "function") {
    [start, end] = [range2.index, range2.index + range2.length].map((pos) => (
      // @ts-expect-error -- TODO: add a better type guard around `index`
      index.transformPosition(pos, source !== emitter_default.sources.USER)
    ));
  } else {
    [start, end] = [range2.index, range2.index + range2.length].map((pos) => {
      if (pos < index || pos === index && source === emitter_default.sources.USER) return pos;
      if (length >= 0) {
        return pos + length;
      }
      return Math.max(index, pos + length);
    });
  }
  return new Range(start, end - start);
}

// node_modules/quill/blots/container.js
var Container = class extends ContainerBlot$1 {
};
var container_default = Container;

// node_modules/quill/blots/scroll.js
var import_quill_delta4 = __toESM(require_Delta(), 1);
function isLine(blot) {
  return blot instanceof Block || blot instanceof BlockEmbed;
}
function isUpdatable(blot) {
  return typeof blot.updateContent === "function";
}
var Scroll = class extends ScrollBlot$1 {
  static blotName = "scroll";
  static className = "ql-editor";
  static tagName = "DIV";
  static defaultChild = Block;
  static allowedChildren = [Block, BlockEmbed, container_default];
  constructor(registry, domNode, _ref) {
    let {
      emitter
    } = _ref;
    super(registry, domNode);
    this.emitter = emitter;
    this.batch = false;
    this.optimize();
    this.enable();
    this.domNode.addEventListener("dragstart", (e) => this.handleDragStart(e));
  }
  batchStart() {
    if (!Array.isArray(this.batch)) {
      this.batch = [];
    }
  }
  batchEnd() {
    if (!this.batch) return;
    const mutations = this.batch;
    this.batch = false;
    this.update(mutations);
  }
  emitMount(blot) {
    this.emitter.emit(emitter_default.events.SCROLL_BLOT_MOUNT, blot);
  }
  emitUnmount(blot) {
    this.emitter.emit(emitter_default.events.SCROLL_BLOT_UNMOUNT, blot);
  }
  emitEmbedUpdate(blot, change) {
    this.emitter.emit(emitter_default.events.SCROLL_EMBED_UPDATE, blot, change);
  }
  deleteAt(index, length) {
    const [first, offset] = this.line(index);
    const [last2] = this.line(index + length);
    super.deleteAt(index, length);
    if (last2 != null && first !== last2 && offset > 0) {
      if (first instanceof BlockEmbed || last2 instanceof BlockEmbed) {
        this.optimize();
        return;
      }
      const ref = last2.children.head instanceof break_default ? null : last2.children.head;
      first.moveChildren(last2, ref);
      first.remove();
    }
    this.optimize();
  }
  enable() {
    let enabled = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : true;
    this.domNode.setAttribute("contenteditable", enabled ? "true" : "false");
  }
  formatAt(index, length, format, value) {
    super.formatAt(index, length, format, value);
    this.optimize();
  }
  insertAt(index, value, def) {
    if (index >= this.length()) {
      if (def == null || this.scroll.query(value, Scope.BLOCK) == null) {
        const blot = this.scroll.create(this.statics.defaultChild.blotName);
        this.appendChild(blot);
        if (def == null && value.endsWith("\n")) {
          blot.insertAt(0, value.slice(0, -1), def);
        } else {
          blot.insertAt(0, value, def);
        }
      } else {
        const embed = this.scroll.create(value, def);
        this.appendChild(embed);
      }
    } else {
      super.insertAt(index, value, def);
    }
    this.optimize();
  }
  insertBefore(blot, ref) {
    if (blot.statics.scope === Scope.INLINE_BLOT) {
      const wrapper = this.scroll.create(this.statics.defaultChild.blotName);
      wrapper.appendChild(blot);
      super.insertBefore(wrapper, ref);
    } else {
      super.insertBefore(blot, ref);
    }
  }
  insertContents(index, delta) {
    const renderBlocks = this.deltaToRenderBlocks(delta.concat(new import_quill_delta4.default().insert("\n")));
    const last2 = renderBlocks.pop();
    if (last2 == null) return;
    this.batchStart();
    const first = renderBlocks.shift();
    if (first) {
      const shouldInsertNewlineChar = first.type === "block" && (first.delta.length() === 0 || !this.descendant(BlockEmbed, index)[0] && index < this.length());
      const delta2 = first.type === "block" ? first.delta : new import_quill_delta4.default().insert({
        [first.key]: first.value
      });
      insertInlineContents(this, index, delta2);
      const newlineCharLength = first.type === "block" ? 1 : 0;
      const lineEndIndex = index + delta2.length() + newlineCharLength;
      if (shouldInsertNewlineChar) {
        this.insertAt(lineEndIndex - 1, "\n");
      }
      const formats = bubbleFormats(this.line(index)[0]);
      const attributes = import_quill_delta4.AttributeMap.diff(formats, first.attributes) || {};
      Object.keys(attributes).forEach((name) => {
        this.formatAt(lineEndIndex - 1, 1, name, attributes[name]);
      });
      index = lineEndIndex;
    }
    let [refBlot, refBlotOffset] = this.children.find(index);
    if (renderBlocks.length) {
      if (refBlot) {
        refBlot = refBlot.split(refBlotOffset);
        refBlotOffset = 0;
      }
      renderBlocks.forEach((renderBlock) => {
        if (renderBlock.type === "block") {
          const block = this.createBlock(renderBlock.attributes, refBlot || void 0);
          insertInlineContents(block, 0, renderBlock.delta);
        } else {
          const blockEmbed = this.create(renderBlock.key, renderBlock.value);
          this.insertBefore(blockEmbed, refBlot || void 0);
          Object.keys(renderBlock.attributes).forEach((name) => {
            blockEmbed.format(name, renderBlock.attributes[name]);
          });
        }
      });
    }
    if (last2.type === "block" && last2.delta.length()) {
      const offset = refBlot ? refBlot.offset(refBlot.scroll) + refBlotOffset : this.length();
      insertInlineContents(this, offset, last2.delta);
    }
    this.batchEnd();
    this.optimize();
  }
  isEnabled() {
    return this.domNode.getAttribute("contenteditable") === "true";
  }
  leaf(index) {
    const last2 = this.path(index).pop();
    if (!last2) {
      return [null, -1];
    }
    const [blot, offset] = last2;
    return blot instanceof LeafBlot$1 ? [blot, offset] : [null, -1];
  }
  line(index) {
    if (index === this.length()) {
      return this.line(index - 1);
    }
    return this.descendant(isLine, index);
  }
  lines() {
    let index = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : 0;
    let length = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : Number.MAX_VALUE;
    const getLines = (blot, blotIndex, blotLength) => {
      let lines = [];
      let lengthLeft = blotLength;
      blot.children.forEachAt(blotIndex, blotLength, (child, childIndex, childLength) => {
        if (isLine(child)) {
          lines.push(child);
        } else if (child instanceof ContainerBlot$1) {
          lines = lines.concat(getLines(child, childIndex, lengthLeft));
        }
        lengthLeft -= childLength;
      });
      return lines;
    };
    return getLines(this, index, length);
  }
  optimize() {
    let mutations = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : [];
    let context = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : {};
    if (this.batch) return;
    super.optimize(mutations, context);
    if (mutations.length > 0) {
      this.emitter.emit(emitter_default.events.SCROLL_OPTIMIZE, mutations, context);
    }
  }
  path(index) {
    return super.path(index).slice(1);
  }
  remove() {
  }
  update(mutations) {
    if (this.batch) {
      if (Array.isArray(mutations)) {
        this.batch = this.batch.concat(mutations);
      }
      return;
    }
    let source = emitter_default.sources.USER;
    if (typeof mutations === "string") {
      source = mutations;
    }
    if (!Array.isArray(mutations)) {
      mutations = this.observer.takeRecords();
    }
    mutations = mutations.filter((_ref2) => {
      let {
        target
      } = _ref2;
      const blot = this.find(target, true);
      return blot && !isUpdatable(blot);
    });
    if (mutations.length > 0) {
      this.emitter.emit(emitter_default.events.SCROLL_BEFORE_UPDATE, source, mutations);
    }
    super.update(mutations.concat([]));
    if (mutations.length > 0) {
      this.emitter.emit(emitter_default.events.SCROLL_UPDATE, source, mutations);
    }
  }
  updateEmbedAt(index, key, change) {
    const [blot] = this.descendant((b) => b instanceof BlockEmbed, index);
    if (blot && blot.statics.blotName === key && isUpdatable(blot)) {
      blot.updateContent(change);
    }
  }
  handleDragStart(event) {
    event.preventDefault();
  }
  deltaToRenderBlocks(delta) {
    const renderBlocks = [];
    let currentBlockDelta = new import_quill_delta4.default();
    delta.forEach((op) => {
      const insert = op?.insert;
      if (!insert) return;
      if (typeof insert === "string") {
        const splitted = insert.split("\n");
        splitted.slice(0, -1).forEach((text) => {
          currentBlockDelta.insert(text, op.attributes);
          renderBlocks.push({
            type: "block",
            delta: currentBlockDelta,
            attributes: op.attributes ?? {}
          });
          currentBlockDelta = new import_quill_delta4.default();
        });
        const last2 = splitted[splitted.length - 1];
        if (last2) {
          currentBlockDelta.insert(last2, op.attributes);
        }
      } else {
        const key = Object.keys(insert)[0];
        if (!key) return;
        if (this.query(key, Scope.INLINE)) {
          currentBlockDelta.push(op);
        } else {
          if (currentBlockDelta.length()) {
            renderBlocks.push({
              type: "block",
              delta: currentBlockDelta,
              attributes: {}
            });
          }
          currentBlockDelta = new import_quill_delta4.default();
          renderBlocks.push({
            type: "blockEmbed",
            key,
            value: insert[key],
            attributes: op.attributes ?? {}
          });
        }
      }
    });
    if (currentBlockDelta.length()) {
      renderBlocks.push({
        type: "block",
        delta: currentBlockDelta,
        attributes: {}
      });
    }
    return renderBlocks;
  }
  createBlock(attributes, refBlot) {
    let blotName;
    const formats = {};
    Object.entries(attributes).forEach((_ref3) => {
      let [key, value] = _ref3;
      const isBlockBlot = this.query(key, Scope.BLOCK & Scope.BLOT) != null;
      if (isBlockBlot) {
        blotName = key;
      } else {
        formats[key] = value;
      }
    });
    const block = this.create(blotName || this.statics.defaultChild.blotName, blotName ? attributes[blotName] : void 0);
    this.insertBefore(block, refBlot || void 0);
    const length = block.length();
    Object.entries(formats).forEach((_ref4) => {
      let [key, value] = _ref4;
      block.formatAt(0, length, key, value);
    });
    return block;
  }
};
function insertInlineContents(parent2, index, inlineContents) {
  inlineContents.reduce((index2, op) => {
    const length = import_quill_delta4.Op.length(op);
    let attributes = op.attributes || {};
    if (op.insert != null) {
      if (typeof op.insert === "string") {
        const text = op.insert;
        parent2.insertAt(index2, text);
        const [leaf] = parent2.descendant(LeafBlot$1, index2);
        const formats = bubbleFormats(leaf);
        attributes = import_quill_delta4.AttributeMap.diff(formats, attributes) || {};
      } else if (typeof op.insert === "object") {
        const key = Object.keys(op.insert)[0];
        if (key == null) return index2;
        parent2.insertAt(index2, key, op.insert[key]);
        const isInlineEmbed = parent2.scroll.query(key, Scope.INLINE) != null;
        if (isInlineEmbed) {
          const [leaf] = parent2.descendant(LeafBlot$1, index2);
          const formats = bubbleFormats(leaf);
          attributes = import_quill_delta4.AttributeMap.diff(formats, attributes) || {};
        }
      }
    }
    Object.keys(attributes).forEach((key) => {
      parent2.formatAt(index2, length, key, attributes[key]);
    });
    return index2 + length;
  }, index);
}
var scroll_default = Scroll;

// node_modules/quill/modules/clipboard.js
var import_quill_delta6 = __toESM(require_Delta(), 1);

// node_modules/quill/formats/align.js
var config = {
  scope: Scope.BLOCK,
  whitelist: ["right", "center", "justify"]
};
var AlignAttribute = new Attributor("align", "align", config);
var AlignClass = new ClassAttributor$1("align", "ql-align", config);
var AlignStyle = new StyleAttributor$1("align", "text-align", config);

// node_modules/quill/formats/color.js
var ColorAttributor = class extends StyleAttributor$1 {
  value(domNode) {
    let value = super.value(domNode);
    if (!value.startsWith("rgb(")) return value;
    value = value.replace(/^[^\d]+/, "").replace(/[^\d]+$/, "");
    const hex = value.split(",").map((component) => `00${parseInt(component, 10).toString(16)}`.slice(-2)).join("");
    return `#${hex}`;
  }
};
var ColorClass = new ClassAttributor$1("color", "ql-color", {
  scope: Scope.INLINE
});
var ColorStyle = new ColorAttributor("color", "color", {
  scope: Scope.INLINE
});

// node_modules/quill/formats/background.js
var BackgroundClass = new ClassAttributor$1("background", "ql-bg", {
  scope: Scope.INLINE
});
var BackgroundStyle = new ColorAttributor("background", "background-color", {
  scope: Scope.INLINE
});

// node_modules/quill/formats/code.js
var CodeBlockContainer = class extends container_default {
  static create(value) {
    const domNode = super.create(value);
    domNode.setAttribute("spellcheck", "false");
    return domNode;
  }
  code(index, length) {
    return this.children.map((child) => child.length() <= 1 ? "" : child.domNode.innerText).join("\n").slice(index, index + length);
  }
  html(index, length) {
    return `<pre>
${escapeText(this.code(index, length))}
</pre>`;
  }
};
var CodeBlock = class extends Block {
  static TAB = "  ";
  static register() {
    Quill.register(CodeBlockContainer);
  }
};
var Code = class extends inline_default {
};
Code.blotName = "code";
Code.tagName = "CODE";
CodeBlock.blotName = "code-block";
CodeBlock.className = "ql-code-block";
CodeBlock.tagName = "DIV";
CodeBlockContainer.blotName = "code-block-container";
CodeBlockContainer.className = "ql-code-block-container";
CodeBlockContainer.tagName = "DIV";
CodeBlockContainer.allowedChildren = [CodeBlock];
CodeBlock.allowedChildren = [Text2, break_default, cursor_default];
CodeBlock.requiredContainer = CodeBlockContainer;

// node_modules/quill/formats/direction.js
var config2 = {
  scope: Scope.BLOCK,
  whitelist: ["rtl"]
};
var DirectionAttribute = new Attributor("direction", "dir", config2);
var DirectionClass = new ClassAttributor$1("direction", "ql-direction", config2);
var DirectionStyle = new StyleAttributor$1("direction", "direction", config2);

// node_modules/quill/formats/font.js
var config3 = {
  scope: Scope.INLINE,
  whitelist: ["serif", "monospace"]
};
var FontClass = new ClassAttributor$1("font", "ql-font", config3);
var FontStyleAttributor = class extends StyleAttributor$1 {
  value(node) {
    return super.value(node).replace(/["']/g, "");
  }
};
var FontStyle = new FontStyleAttributor("font", "font-family", config3);

// node_modules/quill/formats/size.js
var SizeClass = new ClassAttributor$1("size", "ql-size", {
  scope: Scope.INLINE,
  whitelist: ["small", "large", "huge"]
});
var SizeStyle = new StyleAttributor$1("size", "font-size", {
  scope: Scope.INLINE,
  whitelist: ["10px", "18px", "32px"]
});

// node_modules/quill/modules/keyboard.js
var import_quill_delta5 = __toESM(require_Delta(), 1);
var debug5 = logger_default("quill:keyboard");
var SHORTKEY = /Mac/i.test(navigator.platform) ? "metaKey" : "ctrlKey";
var Keyboard = class _Keyboard extends module_default {
  static match(evt, binding) {
    if (["altKey", "ctrlKey", "metaKey", "shiftKey"].some((key) => {
      return !!binding[key] !== evt[key] && binding[key] !== null;
    })) {
      return false;
    }
    return binding.key === evt.key || binding.key === evt.which;
  }
  constructor(quill, options) {
    super(quill, options);
    this.bindings = {};
    Object.keys(this.options.bindings).forEach((name) => {
      if (this.options.bindings[name]) {
        this.addBinding(this.options.bindings[name]);
      }
    });
    this.addBinding({
      key: "Enter",
      shiftKey: null
    }, this.handleEnter);
    this.addBinding({
      key: "Enter",
      metaKey: null,
      ctrlKey: null,
      altKey: null
    }, () => {
    });
    if (/Firefox/i.test(navigator.userAgent)) {
      this.addBinding({
        key: "Backspace"
      }, {
        collapsed: true
      }, this.handleBackspace);
      this.addBinding({
        key: "Delete"
      }, {
        collapsed: true
      }, this.handleDelete);
    } else {
      this.addBinding({
        key: "Backspace"
      }, {
        collapsed: true,
        prefix: /^.?$/
      }, this.handleBackspace);
      this.addBinding({
        key: "Delete"
      }, {
        collapsed: true,
        suffix: /^.?$/
      }, this.handleDelete);
    }
    this.addBinding({
      key: "Backspace"
    }, {
      collapsed: false
    }, this.handleDeleteRange);
    this.addBinding({
      key: "Delete"
    }, {
      collapsed: false
    }, this.handleDeleteRange);
    this.addBinding({
      key: "Backspace",
      altKey: null,
      ctrlKey: null,
      metaKey: null,
      shiftKey: null
    }, {
      collapsed: true,
      offset: 0
    }, this.handleBackspace);
    this.listen();
  }
  addBinding(keyBinding) {
    let context = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : {};
    let handler = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : {};
    const binding = normalize(keyBinding);
    if (binding == null) {
      debug5.warn("Attempted to add invalid keyboard binding", binding);
      return;
    }
    if (typeof context === "function") {
      context = {
        handler: context
      };
    }
    if (typeof handler === "function") {
      handler = {
        handler
      };
    }
    const keys2 = Array.isArray(binding.key) ? binding.key : [binding.key];
    keys2.forEach((key) => {
      const singleBinding = __spreadValues(__spreadValues(__spreadProps(__spreadValues({}, binding), {
        key
      }), context), handler);
      this.bindings[singleBinding.key] = this.bindings[singleBinding.key] || [];
      this.bindings[singleBinding.key].push(singleBinding);
    });
  }
  listen() {
    this.quill.root.addEventListener("keydown", (evt) => {
      if (evt.defaultPrevented || evt.isComposing) return;
      const isComposing = evt.keyCode === 229 && (evt.key === "Enter" || evt.key === "Backspace");
      if (isComposing) return;
      const bindings = (this.bindings[evt.key] || []).concat(this.bindings[evt.which] || []);
      const matches2 = bindings.filter((binding) => _Keyboard.match(evt, binding));
      if (matches2.length === 0) return;
      const blot = Quill.find(evt.target, true);
      if (blot && blot.scroll !== this.quill.scroll) return;
      const range2 = this.quill.getSelection();
      if (range2 == null || !this.quill.hasFocus()) return;
      const [line, offset] = this.quill.getLine(range2.index);
      const [leafStart, offsetStart] = this.quill.getLeaf(range2.index);
      const [leafEnd, offsetEnd] = range2.length === 0 ? [leafStart, offsetStart] : this.quill.getLeaf(range2.index + range2.length);
      const prefixText = leafStart instanceof TextBlot$1 ? leafStart.value().slice(0, offsetStart) : "";
      const suffixText = leafEnd instanceof TextBlot$1 ? leafEnd.value().slice(offsetEnd) : "";
      const curContext = {
        collapsed: range2.length === 0,
        // @ts-expect-error Fix me later
        empty: range2.length === 0 && line.length() <= 1,
        format: this.quill.getFormat(range2),
        line,
        offset,
        prefix: prefixText,
        suffix: suffixText,
        event: evt
      };
      const prevented = matches2.some((binding) => {
        if (binding.collapsed != null && binding.collapsed !== curContext.collapsed) {
          return false;
        }
        if (binding.empty != null && binding.empty !== curContext.empty) {
          return false;
        }
        if (binding.offset != null && binding.offset !== curContext.offset) {
          return false;
        }
        if (Array.isArray(binding.format)) {
          if (binding.format.every((name) => curContext.format[name] == null)) {
            return false;
          }
        } else if (typeof binding.format === "object") {
          if (!Object.keys(binding.format).every((name) => {
            if (binding.format[name] === true) return curContext.format[name] != null;
            if (binding.format[name] === false) return curContext.format[name] == null;
            return isEqual_default(binding.format[name], curContext.format[name]);
          })) {
            return false;
          }
        }
        if (binding.prefix != null && !binding.prefix.test(curContext.prefix)) {
          return false;
        }
        if (binding.suffix != null && !binding.suffix.test(curContext.suffix)) {
          return false;
        }
        return binding.handler.call(this, range2, curContext, binding) !== true;
      });
      if (prevented) {
        evt.preventDefault();
      }
    });
  }
  handleBackspace(range2, context) {
    const length = /[\uD800-\uDBFF][\uDC00-\uDFFF]$/.test(context.prefix) ? 2 : 1;
    if (range2.index === 0 || this.quill.getLength() <= 1) return;
    let formats = {};
    const [line] = this.quill.getLine(range2.index);
    let delta = new import_quill_delta5.default().retain(range2.index - length).delete(length);
    if (context.offset === 0) {
      const [prev] = this.quill.getLine(range2.index - 1);
      if (prev) {
        const isPrevLineEmpty = prev.statics.blotName === "block" && prev.length() <= 1;
        if (!isPrevLineEmpty) {
          const curFormats = line.formats();
          const prevFormats = this.quill.getFormat(range2.index - 1, 1);
          formats = import_quill_delta5.AttributeMap.diff(curFormats, prevFormats) || {};
          if (Object.keys(formats).length > 0) {
            const formatDelta = new import_quill_delta5.default().retain(range2.index + line.length() - 2).retain(1, formats);
            delta = delta.compose(formatDelta);
          }
        }
      }
    }
    this.quill.updateContents(delta, Quill.sources.USER);
    this.quill.focus();
  }
  handleDelete(range2, context) {
    const length = /^[\uD800-\uDBFF][\uDC00-\uDFFF]/.test(context.suffix) ? 2 : 1;
    if (range2.index >= this.quill.getLength() - length) return;
    let formats = {};
    const [line] = this.quill.getLine(range2.index);
    let delta = new import_quill_delta5.default().retain(range2.index).delete(length);
    if (context.offset >= line.length() - 1) {
      const [next] = this.quill.getLine(range2.index + 1);
      if (next) {
        const curFormats = line.formats();
        const nextFormats = this.quill.getFormat(range2.index, 1);
        formats = import_quill_delta5.AttributeMap.diff(curFormats, nextFormats) || {};
        if (Object.keys(formats).length > 0) {
          delta = delta.retain(next.length() - 1).retain(1, formats);
        }
      }
    }
    this.quill.updateContents(delta, Quill.sources.USER);
    this.quill.focus();
  }
  handleDeleteRange(range2) {
    deleteRange({
      range: range2,
      quill: this.quill
    });
    this.quill.focus();
  }
  handleEnter(range2, context) {
    const lineFormats = Object.keys(context.format).reduce((formats, format) => {
      if (this.quill.scroll.query(format, Scope.BLOCK) && !Array.isArray(context.format[format])) {
        formats[format] = context.format[format];
      }
      return formats;
    }, {});
    const delta = new import_quill_delta5.default().retain(range2.index).delete(range2.length).insert("\n", lineFormats);
    this.quill.updateContents(delta, Quill.sources.USER);
    this.quill.setSelection(range2.index + 1, Quill.sources.SILENT);
    this.quill.focus();
  }
};
var defaultOptions = {
  bindings: {
    bold: makeFormatHandler("bold"),
    italic: makeFormatHandler("italic"),
    underline: makeFormatHandler("underline"),
    indent: {
      // highlight tab or tab at beginning of list, indent or blockquote
      key: "Tab",
      format: ["blockquote", "indent", "list"],
      handler(range2, context) {
        if (context.collapsed && context.offset !== 0) return true;
        this.quill.format("indent", "+1", Quill.sources.USER);
        return false;
      }
    },
    outdent: {
      key: "Tab",
      shiftKey: true,
      format: ["blockquote", "indent", "list"],
      // highlight tab or tab at beginning of list, indent or blockquote
      handler(range2, context) {
        if (context.collapsed && context.offset !== 0) return true;
        this.quill.format("indent", "-1", Quill.sources.USER);
        return false;
      }
    },
    "outdent backspace": {
      key: "Backspace",
      collapsed: true,
      shiftKey: null,
      metaKey: null,
      ctrlKey: null,
      altKey: null,
      format: ["indent", "list"],
      offset: 0,
      handler(range2, context) {
        if (context.format.indent != null) {
          this.quill.format("indent", "-1", Quill.sources.USER);
        } else if (context.format.list != null) {
          this.quill.format("list", false, Quill.sources.USER);
        }
      }
    },
    "indent code-block": makeCodeBlockHandler(true),
    "outdent code-block": makeCodeBlockHandler(false),
    "remove tab": {
      key: "Tab",
      shiftKey: true,
      collapsed: true,
      prefix: /\t$/,
      handler(range2) {
        this.quill.deleteText(range2.index - 1, 1, Quill.sources.USER);
      }
    },
    tab: {
      key: "Tab",
      handler(range2, context) {
        if (context.format.table) return true;
        this.quill.history.cutoff();
        const delta = new import_quill_delta5.default().retain(range2.index).delete(range2.length).insert("	");
        this.quill.updateContents(delta, Quill.sources.USER);
        this.quill.history.cutoff();
        this.quill.setSelection(range2.index + 1, Quill.sources.SILENT);
        return false;
      }
    },
    "blockquote empty enter": {
      key: "Enter",
      collapsed: true,
      format: ["blockquote"],
      empty: true,
      handler() {
        this.quill.format("blockquote", false, Quill.sources.USER);
      }
    },
    "list empty enter": {
      key: "Enter",
      collapsed: true,
      format: ["list"],
      empty: true,
      handler(range2, context) {
        const formats = {
          list: false
        };
        if (context.format.indent) {
          formats.indent = false;
        }
        this.quill.formatLine(range2.index, range2.length, formats, Quill.sources.USER);
      }
    },
    "checklist enter": {
      key: "Enter",
      collapsed: true,
      format: {
        list: "checked"
      },
      handler(range2) {
        const [line, offset] = this.quill.getLine(range2.index);
        const formats = __spreadProps(__spreadValues({}, line.formats()), {
          list: "checked"
        });
        const delta = new import_quill_delta5.default().retain(range2.index).insert("\n", formats).retain(line.length() - offset - 1).retain(1, {
          list: "unchecked"
        });
        this.quill.updateContents(delta, Quill.sources.USER);
        this.quill.setSelection(range2.index + 1, Quill.sources.SILENT);
        this.quill.scrollSelectionIntoView();
      }
    },
    "header enter": {
      key: "Enter",
      collapsed: true,
      format: ["header"],
      suffix: /^$/,
      handler(range2, context) {
        const [line, offset] = this.quill.getLine(range2.index);
        const delta = new import_quill_delta5.default().retain(range2.index).insert("\n", context.format).retain(line.length() - offset - 1).retain(1, {
          header: null
        });
        this.quill.updateContents(delta, Quill.sources.USER);
        this.quill.setSelection(range2.index + 1, Quill.sources.SILENT);
        this.quill.scrollSelectionIntoView();
      }
    },
    "table backspace": {
      key: "Backspace",
      format: ["table"],
      collapsed: true,
      offset: 0,
      handler() {
      }
    },
    "table delete": {
      key: "Delete",
      format: ["table"],
      collapsed: true,
      suffix: /^$/,
      handler() {
      }
    },
    "table enter": {
      key: "Enter",
      shiftKey: null,
      format: ["table"],
      handler(range2) {
        const module2 = this.quill.getModule("table");
        if (module2) {
          const [table, row, cell, offset] = module2.getTable(range2);
          const shift = tableSide(table, row, cell, offset);
          if (shift == null) return;
          let index = table.offset();
          if (shift < 0) {
            const delta = new import_quill_delta5.default().retain(index).insert("\n");
            this.quill.updateContents(delta, Quill.sources.USER);
            this.quill.setSelection(range2.index + 1, range2.length, Quill.sources.SILENT);
          } else if (shift > 0) {
            index += table.length();
            const delta = new import_quill_delta5.default().retain(index).insert("\n");
            this.quill.updateContents(delta, Quill.sources.USER);
            this.quill.setSelection(index, Quill.sources.USER);
          }
        }
      }
    },
    "table tab": {
      key: "Tab",
      shiftKey: null,
      format: ["table"],
      handler(range2, context) {
        const {
          event,
          line: cell
        } = context;
        const offset = cell.offset(this.quill.scroll);
        if (event.shiftKey) {
          this.quill.setSelection(offset - 1, Quill.sources.USER);
        } else {
          this.quill.setSelection(offset + cell.length(), Quill.sources.USER);
        }
      }
    },
    "list autofill": {
      key: " ",
      shiftKey: null,
      collapsed: true,
      format: {
        "code-block": false,
        blockquote: false,
        table: false
      },
      prefix: /^\s*?(\d+\.|-|\*|\[ ?\]|\[x\])$/,
      handler(range2, context) {
        if (this.quill.scroll.query("list") == null) return true;
        const {
          length
        } = context.prefix;
        const [line, offset] = this.quill.getLine(range2.index);
        if (offset > length) return true;
        let value;
        switch (context.prefix.trim()) {
          case "[]":
          case "[ ]":
            value = "unchecked";
            break;
          case "[x]":
            value = "checked";
            break;
          case "-":
          case "*":
            value = "bullet";
            break;
          default:
            value = "ordered";
        }
        this.quill.insertText(range2.index, " ", Quill.sources.USER);
        this.quill.history.cutoff();
        const delta = new import_quill_delta5.default().retain(range2.index - offset).delete(length + 1).retain(line.length() - 2 - offset).retain(1, {
          list: value
        });
        this.quill.updateContents(delta, Quill.sources.USER);
        this.quill.history.cutoff();
        this.quill.setSelection(range2.index - length, Quill.sources.SILENT);
        return false;
      }
    },
    "code exit": {
      key: "Enter",
      collapsed: true,
      format: ["code-block"],
      prefix: /^$/,
      suffix: /^\s*$/,
      handler(range2) {
        const [line, offset] = this.quill.getLine(range2.index);
        let numLines = 2;
        let cur = line;
        while (cur != null && cur.length() <= 1 && cur.formats()["code-block"]) {
          cur = cur.prev;
          numLines -= 1;
          if (numLines <= 0) {
            const delta = new import_quill_delta5.default().retain(range2.index + line.length() - offset - 2).retain(1, {
              "code-block": null
            }).delete(1);
            this.quill.updateContents(delta, Quill.sources.USER);
            this.quill.setSelection(range2.index - 1, Quill.sources.SILENT);
            return false;
          }
        }
        return true;
      }
    },
    "embed left": makeEmbedArrowHandler("ArrowLeft", false),
    "embed left shift": makeEmbedArrowHandler("ArrowLeft", true),
    "embed right": makeEmbedArrowHandler("ArrowRight", false),
    "embed right shift": makeEmbedArrowHandler("ArrowRight", true),
    "table down": makeTableArrowHandler(false),
    "table up": makeTableArrowHandler(true)
  }
};
Keyboard.DEFAULTS = defaultOptions;
function makeCodeBlockHandler(indent) {
  return {
    key: "Tab",
    shiftKey: !indent,
    format: {
      "code-block": true
    },
    handler(range2, _ref) {
      let {
        event
      } = _ref;
      const CodeBlock2 = this.quill.scroll.query("code-block");
      const {
        TAB
      } = CodeBlock2;
      if (range2.length === 0 && !event.shiftKey) {
        this.quill.insertText(range2.index, TAB, Quill.sources.USER);
        this.quill.setSelection(range2.index + TAB.length, Quill.sources.SILENT);
        return;
      }
      const lines = range2.length === 0 ? this.quill.getLines(range2.index, 1) : this.quill.getLines(range2);
      let {
        index,
        length
      } = range2;
      lines.forEach((line, i) => {
        if (indent) {
          line.insertAt(0, TAB);
          if (i === 0) {
            index += TAB.length;
          } else {
            length += TAB.length;
          }
        } else if (line.domNode.textContent.startsWith(TAB)) {
          line.deleteAt(0, TAB.length);
          if (i === 0) {
            index -= TAB.length;
          } else {
            length -= TAB.length;
          }
        }
      });
      this.quill.update(Quill.sources.USER);
      this.quill.setSelection(index, length, Quill.sources.SILENT);
    }
  };
}
function makeEmbedArrowHandler(key, shiftKey) {
  const where = key === "ArrowLeft" ? "prefix" : "suffix";
  return {
    key,
    shiftKey,
    altKey: null,
    [where]: /^$/,
    handler(range2) {
      let {
        index
      } = range2;
      if (key === "ArrowRight") {
        index += range2.length + 1;
      }
      const [leaf] = this.quill.getLeaf(index);
      if (!(leaf instanceof EmbedBlot$1)) return true;
      if (key === "ArrowLeft") {
        if (shiftKey) {
          this.quill.setSelection(range2.index - 1, range2.length + 1, Quill.sources.USER);
        } else {
          this.quill.setSelection(range2.index - 1, Quill.sources.USER);
        }
      } else if (shiftKey) {
        this.quill.setSelection(range2.index, range2.length + 1, Quill.sources.USER);
      } else {
        this.quill.setSelection(range2.index + range2.length + 1, Quill.sources.USER);
      }
      return false;
    }
  };
}
function makeFormatHandler(format) {
  return {
    key: format[0],
    shortKey: true,
    handler(range2, context) {
      this.quill.format(format, !context.format[format], Quill.sources.USER);
    }
  };
}
function makeTableArrowHandler(up) {
  return {
    key: up ? "ArrowUp" : "ArrowDown",
    collapsed: true,
    format: ["table"],
    handler(range2, context) {
      const key = up ? "prev" : "next";
      const cell = context.line;
      const targetRow = cell.parent[key];
      if (targetRow != null) {
        if (targetRow.statics.blotName === "table-row") {
          let targetCell = targetRow.children.head;
          let cur = cell;
          while (cur.prev != null) {
            cur = cur.prev;
            targetCell = targetCell.next;
          }
          const index = targetCell.offset(this.quill.scroll) + Math.min(context.offset, targetCell.length() - 1);
          this.quill.setSelection(index, 0, Quill.sources.USER);
        }
      } else {
        const targetLine = cell.table()[key];
        if (targetLine != null) {
          if (up) {
            this.quill.setSelection(targetLine.offset(this.quill.scroll) + targetLine.length() - 1, 0, Quill.sources.USER);
          } else {
            this.quill.setSelection(targetLine.offset(this.quill.scroll), 0, Quill.sources.USER);
          }
        }
      }
      return false;
    }
  };
}
function normalize(binding) {
  if (typeof binding === "string" || typeof binding === "number") {
    binding = {
      key: binding
    };
  } else if (typeof binding === "object") {
    binding = cloneDeep_default(binding);
  } else {
    return null;
  }
  if (binding.shortKey) {
    binding[SHORTKEY] = binding.shortKey;
    delete binding.shortKey;
  }
  return binding;
}
function deleteRange(_ref2) {
  let {
    quill,
    range: range2
  } = _ref2;
  const lines = quill.getLines(range2);
  let formats = {};
  if (lines.length > 1) {
    const firstFormats = lines[0].formats();
    const lastFormats = lines[lines.length - 1].formats();
    formats = import_quill_delta5.AttributeMap.diff(lastFormats, firstFormats) || {};
  }
  quill.deleteText(range2, Quill.sources.USER);
  if (Object.keys(formats).length > 0) {
    quill.formatLine(range2.index, 1, formats, Quill.sources.USER);
  }
  quill.setSelection(range2.index, Quill.sources.SILENT);
}
function tableSide(_table, row, cell, offset) {
  if (row.prev == null && row.next == null) {
    if (cell.prev == null && cell.next == null) {
      return offset === 0 ? -1 : 1;
    }
    return cell.prev == null ? -1 : 1;
  }
  if (row.prev == null) {
    return -1;
  }
  if (row.next == null) {
    return 1;
  }
  return null;
}

// node_modules/quill/modules/normalizeExternalHTML/normalizers/googleDocs.js
var normalWeightRegexp = /font-weight:\s*normal/;
var blockTagNames = ["P", "OL", "UL"];
var isBlockElement = (element) => {
  return element && blockTagNames.includes(element.tagName);
};
var normalizeEmptyLines = (doc) => {
  Array.from(doc.querySelectorAll("br")).filter((br) => isBlockElement(br.previousElementSibling) && isBlockElement(br.nextElementSibling)).forEach((br) => {
    br.parentNode?.removeChild(br);
  });
};
var normalizeFontWeight = (doc) => {
  Array.from(doc.querySelectorAll('b[style*="font-weight"]')).filter((node) => node.getAttribute("style")?.match(normalWeightRegexp)).forEach((node) => {
    const fragment = doc.createDocumentFragment();
    fragment.append(...node.childNodes);
    node.parentNode?.replaceChild(fragment, node);
  });
};
function normalize2(doc) {
  if (doc.querySelector('[id^="docs-internal-guid-"]')) {
    normalizeFontWeight(doc);
    normalizeEmptyLines(doc);
  }
}

// node_modules/quill/modules/normalizeExternalHTML/normalizers/msWord.js
var ignoreRegexp = /\bmso-list:[^;]*ignore/i;
var idRegexp = /\bmso-list:[^;]*\bl(\d+)/i;
var indentRegexp = /\bmso-list:[^;]*\blevel(\d+)/i;
var parseListItem = (element, html) => {
  const style = element.getAttribute("style");
  const idMatch = style?.match(idRegexp);
  if (!idMatch) {
    return null;
  }
  const id = Number(idMatch[1]);
  const indentMatch = style?.match(indentRegexp);
  const indent = indentMatch ? Number(indentMatch[1]) : 1;
  const typeRegexp = new RegExp(`@list l${id}:level${indent}\\s*\\{[^\\}]*mso-level-number-format:\\s*([\\w-]+)`, "i");
  const typeMatch = html.match(typeRegexp);
  const type = typeMatch && typeMatch[1] === "bullet" ? "bullet" : "ordered";
  return {
    id,
    indent,
    type,
    element
  };
};
var normalizeListItem = (doc) => {
  const msoList = Array.from(doc.querySelectorAll("[style*=mso-list]"));
  const ignored = [];
  const others = [];
  msoList.forEach((node) => {
    const shouldIgnore = (node.getAttribute("style") || "").match(ignoreRegexp);
    if (shouldIgnore) {
      ignored.push(node);
    } else {
      others.push(node);
    }
  });
  ignored.forEach((node) => node.parentNode?.removeChild(node));
  const html = doc.documentElement.innerHTML;
  const listItems = others.map((element) => parseListItem(element, html)).filter((parsed) => parsed);
  while (listItems.length) {
    const childListItems = [];
    let current = listItems.shift();
    while (current) {
      childListItems.push(current);
      current = listItems.length && listItems[0]?.element === current.element.nextElementSibling && // Different id means the next item doesn't belong to this group.
      listItems[0].id === current.id ? listItems.shift() : null;
    }
    const ul = document.createElement("ul");
    childListItems.forEach((listItem) => {
      const li = document.createElement("li");
      li.setAttribute("data-list", listItem.type);
      if (listItem.indent > 1) {
        li.setAttribute("class", `ql-indent-${listItem.indent - 1}`);
      }
      li.innerHTML = listItem.element.innerHTML;
      ul.appendChild(li);
    });
    const element = childListItems[0]?.element;
    const {
      parentNode
    } = element ?? {};
    if (element) {
      parentNode?.replaceChild(ul, element);
    }
    childListItems.slice(1).forEach((_ref) => {
      let {
        element: e
      } = _ref;
      parentNode?.removeChild(e);
    });
  }
};
function normalize3(doc) {
  if (doc.documentElement.getAttribute("xmlns:w") === "urn:schemas-microsoft-com:office:word") {
    normalizeListItem(doc);
  }
}

// node_modules/quill/modules/normalizeExternalHTML/index.js
var NORMALIZERS = [normalize3, normalize2];
var normalizeExternalHTML = (doc) => {
  if (doc.documentElement) {
    NORMALIZERS.forEach((normalize4) => {
      normalize4(doc);
    });
  }
};
var normalizeExternalHTML_default = normalizeExternalHTML;

// node_modules/quill/modules/clipboard.js
var debug6 = logger_default("quill:clipboard");
var CLIPBOARD_CONFIG = [[Node.TEXT_NODE, matchText], [Node.TEXT_NODE, matchNewline], ["br", matchBreak], [Node.ELEMENT_NODE, matchNewline], [Node.ELEMENT_NODE, matchBlot], [Node.ELEMENT_NODE, matchAttributor], [Node.ELEMENT_NODE, matchStyles], ["li", matchIndent], ["ol, ul", matchList], ["pre", matchCodeBlock], ["tr", matchTable], ["b", createMatchAlias("bold")], ["i", createMatchAlias("italic")], ["strike", createMatchAlias("strike")], ["style", matchIgnore]];
var ATTRIBUTE_ATTRIBUTORS = [AlignAttribute, DirectionAttribute].reduce((memo, attr) => {
  memo[attr.keyName] = attr;
  return memo;
}, {});
var STYLE_ATTRIBUTORS = [AlignStyle, BackgroundStyle, ColorStyle, DirectionStyle, FontStyle, SizeStyle].reduce((memo, attr) => {
  memo[attr.keyName] = attr;
  return memo;
}, {});
var Clipboard = class extends module_default {
  static DEFAULTS = {
    matchers: []
  };
  constructor(quill, options) {
    super(quill, options);
    this.quill.root.addEventListener("copy", (e) => this.onCaptureCopy(e, false));
    this.quill.root.addEventListener("cut", (e) => this.onCaptureCopy(e, true));
    this.quill.root.addEventListener("paste", this.onCapturePaste.bind(this));
    this.matchers = [];
    CLIPBOARD_CONFIG.concat(this.options.matchers ?? []).forEach((_ref) => {
      let [selector, matcher] = _ref;
      this.addMatcher(selector, matcher);
    });
  }
  addMatcher(selector, matcher) {
    this.matchers.push([selector, matcher]);
  }
  convert(_ref2) {
    let {
      html,
      text
    } = _ref2;
    let formats = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : {};
    if (formats[CodeBlock.blotName]) {
      return new import_quill_delta6.default().insert(text || "", {
        [CodeBlock.blotName]: formats[CodeBlock.blotName]
      });
    }
    if (!html) {
      return new import_quill_delta6.default().insert(text || "", formats);
    }
    const delta = this.convertHTML(html);
    if (deltaEndsWith(delta, "\n") && (delta.ops[delta.ops.length - 1].attributes == null || formats.table)) {
      return delta.compose(new import_quill_delta6.default().retain(delta.length() - 1).delete(1));
    }
    return delta;
  }
  normalizeHTML(doc) {
    normalizeExternalHTML_default(doc);
  }
  convertHTML(html) {
    const doc = new DOMParser().parseFromString(html, "text/html");
    this.normalizeHTML(doc);
    const container = doc.body;
    const nodeMatches = /* @__PURE__ */ new WeakMap();
    const [elementMatchers, textMatchers] = this.prepareMatching(container, nodeMatches);
    return traverse(this.quill.scroll, container, elementMatchers, textMatchers, nodeMatches);
  }
  dangerouslyPasteHTML(index, html) {
    let source = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : Quill.sources.API;
    if (typeof index === "string") {
      const delta = this.convert({
        html: index,
        text: ""
      });
      this.quill.setContents(delta, html);
      this.quill.setSelection(0, Quill.sources.SILENT);
    } else {
      const paste = this.convert({
        html,
        text: ""
      });
      this.quill.updateContents(new import_quill_delta6.default().retain(index).concat(paste), source);
      this.quill.setSelection(index + paste.length(), Quill.sources.SILENT);
    }
  }
  onCaptureCopy(e) {
    let isCut = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : false;
    if (e.defaultPrevented) return;
    e.preventDefault();
    const [range2] = this.quill.selection.getRange();
    if (range2 == null) return;
    const {
      html,
      text
    } = this.onCopy(range2, isCut);
    e.clipboardData?.setData("text/plain", text);
    e.clipboardData?.setData("text/html", html);
    if (isCut) {
      deleteRange({
        range: range2,
        quill: this.quill
      });
    }
  }
  /*
   * https://www.iana.org/assignments/media-types/text/uri-list
   */
  normalizeURIList(urlList) {
    return urlList.split(/\r?\n/).filter((url) => url[0] !== "#").join("\n");
  }
  onCapturePaste(e) {
    if (e.defaultPrevented || !this.quill.isEnabled()) return;
    e.preventDefault();
    const range2 = this.quill.getSelection(true);
    if (range2 == null) return;
    const html = e.clipboardData?.getData("text/html");
    let text = e.clipboardData?.getData("text/plain");
    if (!html && !text) {
      const urlList = e.clipboardData?.getData("text/uri-list");
      if (urlList) {
        text = this.normalizeURIList(urlList);
      }
    }
    const files = Array.from(e.clipboardData?.files || []);
    if (!html && files.length > 0) {
      this.quill.uploader.upload(range2, files);
      return;
    }
    if (html && files.length > 0) {
      const doc = new DOMParser().parseFromString(html, "text/html");
      if (doc.body.childElementCount === 1 && doc.body.firstElementChild?.tagName === "IMG") {
        this.quill.uploader.upload(range2, files);
        return;
      }
    }
    this.onPaste(range2, {
      html,
      text
    });
  }
  onCopy(range2) {
    const text = this.quill.getText(range2);
    const html = this.quill.getSemanticHTML(range2);
    return {
      html,
      text
    };
  }
  onPaste(range2, _ref3) {
    let {
      text,
      html
    } = _ref3;
    const formats = this.quill.getFormat(range2.index);
    const pastedDelta = this.convert({
      text,
      html
    }, formats);
    debug6.log("onPaste", pastedDelta, {
      text,
      html
    });
    const delta = new import_quill_delta6.default().retain(range2.index).delete(range2.length).concat(pastedDelta);
    this.quill.updateContents(delta, Quill.sources.USER);
    this.quill.setSelection(delta.length() - range2.length, Quill.sources.SILENT);
    this.quill.scrollSelectionIntoView();
  }
  prepareMatching(container, nodeMatches) {
    const elementMatchers = [];
    const textMatchers = [];
    this.matchers.forEach((pair) => {
      const [selector, matcher] = pair;
      switch (selector) {
        case Node.TEXT_NODE:
          textMatchers.push(matcher);
          break;
        case Node.ELEMENT_NODE:
          elementMatchers.push(matcher);
          break;
        default:
          Array.from(container.querySelectorAll(selector)).forEach((node) => {
            if (nodeMatches.has(node)) {
              const matches2 = nodeMatches.get(node);
              matches2?.push(matcher);
            } else {
              nodeMatches.set(node, [matcher]);
            }
          });
          break;
      }
    });
    return [elementMatchers, textMatchers];
  }
};
function applyFormat(delta, format, value, scroll) {
  if (!scroll.query(format)) {
    return delta;
  }
  return delta.reduce((newDelta, op) => {
    if (!op.insert) return newDelta;
    if (op.attributes && op.attributes[format]) {
      return newDelta.push(op);
    }
    const formats = value ? {
      [format]: value
    } : {};
    return newDelta.insert(op.insert, __spreadValues(__spreadValues({}, formats), op.attributes));
  }, new import_quill_delta6.default());
}
function deltaEndsWith(delta, text) {
  let endText = "";
  for (let i = delta.ops.length - 1; i >= 0 && endText.length < text.length; --i) {
    const op = delta.ops[i];
    if (typeof op.insert !== "string") break;
    endText = op.insert + endText;
  }
  return endText.slice(-1 * text.length) === text;
}
function isLine2(node, scroll) {
  if (!(node instanceof Element)) return false;
  const match2 = scroll.query(node);
  if (match2 && match2.prototype instanceof EmbedBlot$1) return false;
  return ["address", "article", "blockquote", "canvas", "dd", "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "iframe", "li", "main", "nav", "ol", "output", "p", "pre", "section", "table", "td", "tr", "ul", "video"].includes(node.tagName.toLowerCase());
}
function isBetweenInlineElements(node, scroll) {
  return node.previousElementSibling && node.nextElementSibling && !isLine2(node.previousElementSibling, scroll) && !isLine2(node.nextElementSibling, scroll);
}
var preNodes = /* @__PURE__ */ new WeakMap();
function isPre(node) {
  if (node == null) return false;
  if (!preNodes.has(node)) {
    if (node.tagName === "PRE") {
      preNodes.set(node, true);
    } else {
      preNodes.set(node, isPre(node.parentNode));
    }
  }
  return preNodes.get(node);
}
function traverse(scroll, node, elementMatchers, textMatchers, nodeMatches) {
  if (node.nodeType === node.TEXT_NODE) {
    return textMatchers.reduce((delta, matcher) => {
      return matcher(node, delta, scroll);
    }, new import_quill_delta6.default());
  }
  if (node.nodeType === node.ELEMENT_NODE) {
    return Array.from(node.childNodes || []).reduce((delta, childNode) => {
      let childrenDelta = traverse(scroll, childNode, elementMatchers, textMatchers, nodeMatches);
      if (childNode.nodeType === node.ELEMENT_NODE) {
        childrenDelta = elementMatchers.reduce((reducedDelta, matcher) => {
          return matcher(childNode, reducedDelta, scroll);
        }, childrenDelta);
        childrenDelta = (nodeMatches.get(childNode) || []).reduce((reducedDelta, matcher) => {
          return matcher(childNode, reducedDelta, scroll);
        }, childrenDelta);
      }
      return delta.concat(childrenDelta);
    }, new import_quill_delta6.default());
  }
  return new import_quill_delta6.default();
}
function createMatchAlias(format) {
  return (_node, delta, scroll) => {
    return applyFormat(delta, format, true, scroll);
  };
}
function matchAttributor(node, delta, scroll) {
  const attributes = Attributor.keys(node);
  const classes = ClassAttributor$1.keys(node);
  const styles = StyleAttributor$1.keys(node);
  const formats = {};
  attributes.concat(classes).concat(styles).forEach((name) => {
    let attr = scroll.query(name, Scope.ATTRIBUTE);
    if (attr != null) {
      formats[attr.attrName] = attr.value(node);
      if (formats[attr.attrName]) return;
    }
    attr = ATTRIBUTE_ATTRIBUTORS[name];
    if (attr != null && (attr.attrName === name || attr.keyName === name)) {
      formats[attr.attrName] = attr.value(node) || void 0;
    }
    attr = STYLE_ATTRIBUTORS[name];
    if (attr != null && (attr.attrName === name || attr.keyName === name)) {
      attr = STYLE_ATTRIBUTORS[name];
      formats[attr.attrName] = attr.value(node) || void 0;
    }
  });
  return Object.entries(formats).reduce((newDelta, _ref4) => {
    let [name, value] = _ref4;
    return applyFormat(newDelta, name, value, scroll);
  }, delta);
}
function matchBlot(node, delta, scroll) {
  const match2 = scroll.query(node);
  if (match2 == null) return delta;
  if (match2.prototype instanceof EmbedBlot$1) {
    const embed = {};
    const value = match2.value(node);
    if (value != null) {
      embed[match2.blotName] = value;
      return new import_quill_delta6.default().insert(embed, match2.formats(node, scroll));
    }
  } else {
    if (match2.prototype instanceof BlockBlot$1 && !deltaEndsWith(delta, "\n")) {
      delta.insert("\n");
    }
    if ("blotName" in match2 && "formats" in match2 && typeof match2.formats === "function") {
      return applyFormat(delta, match2.blotName, match2.formats(node, scroll), scroll);
    }
  }
  return delta;
}
function matchBreak(node, delta) {
  if (!deltaEndsWith(delta, "\n")) {
    delta.insert("\n");
  }
  return delta;
}
function matchCodeBlock(node, delta, scroll) {
  const match2 = scroll.query("code-block");
  const language = match2 && "formats" in match2 && typeof match2.formats === "function" ? match2.formats(node, scroll) : true;
  return applyFormat(delta, "code-block", language, scroll);
}
function matchIgnore() {
  return new import_quill_delta6.default();
}
function matchIndent(node, delta, scroll) {
  const match2 = scroll.query(node);
  if (match2 == null || // @ts-expect-error
  match2.blotName !== "list" || !deltaEndsWith(delta, "\n")) {
    return delta;
  }
  let indent = -1;
  let parent2 = node.parentNode;
  while (parent2 != null) {
    if (["OL", "UL"].includes(parent2.tagName)) {
      indent += 1;
    }
    parent2 = parent2.parentNode;
  }
  if (indent <= 0) return delta;
  return delta.reduce((composed, op) => {
    if (!op.insert) return composed;
    if (op.attributes && typeof op.attributes.indent === "number") {
      return composed.push(op);
    }
    return composed.insert(op.insert, __spreadValues({
      indent
    }, op.attributes || {}));
  }, new import_quill_delta6.default());
}
function matchList(node, delta, scroll) {
  const element = node;
  let list = element.tagName === "OL" ? "ordered" : "bullet";
  const checkedAttr = element.getAttribute("data-checked");
  if (checkedAttr) {
    list = checkedAttr === "true" ? "checked" : "unchecked";
  }
  return applyFormat(delta, "list", list, scroll);
}
function matchNewline(node, delta, scroll) {
  if (!deltaEndsWith(delta, "\n")) {
    if (isLine2(node, scroll) && (node.childNodes.length > 0 || node instanceof HTMLParagraphElement)) {
      return delta.insert("\n");
    }
    if (delta.length() > 0 && node.nextSibling) {
      let nextSibling = node.nextSibling;
      while (nextSibling != null) {
        if (isLine2(nextSibling, scroll)) {
          return delta.insert("\n");
        }
        const match2 = scroll.query(nextSibling);
        if (match2 && match2.prototype instanceof BlockEmbed) {
          return delta.insert("\n");
        }
        nextSibling = nextSibling.firstChild;
      }
    }
  }
  return delta;
}
function matchStyles(node, delta, scroll) {
  const formats = {};
  const style = node.style || {};
  if (style.fontStyle === "italic") {
    formats.italic = true;
  }
  if (style.textDecoration === "underline") {
    formats.underline = true;
  }
  if (style.textDecoration === "line-through") {
    formats.strike = true;
  }
  if (style.fontWeight?.startsWith("bold") || // @ts-expect-error Fix me later
  parseInt(style.fontWeight, 10) >= 700) {
    formats.bold = true;
  }
  delta = Object.entries(formats).reduce((newDelta, _ref5) => {
    let [name, value] = _ref5;
    return applyFormat(newDelta, name, value, scroll);
  }, delta);
  if (parseFloat(style.textIndent || 0) > 0) {
    return new import_quill_delta6.default().insert("	").concat(delta);
  }
  return delta;
}
function matchTable(node, delta, scroll) {
  const table = node.parentElement?.tagName === "TABLE" ? node.parentElement : node.parentElement?.parentElement;
  if (table != null) {
    const rows = Array.from(table.querySelectorAll("tr"));
    const row = rows.indexOf(node) + 1;
    return applyFormat(delta, "table", row, scroll);
  }
  return delta;
}
function matchText(node, delta, scroll) {
  let text = node.data;
  if (node.parentElement?.tagName === "O:P") {
    return delta.insert(text.trim());
  }
  if (!isPre(node)) {
    if (text.trim().length === 0 && text.includes("\n") && !isBetweenInlineElements(node, scroll)) {
      return delta;
    }
    text = text.replace(/[^\S\u00a0]/g, " ");
    text = text.replace(/ {2,}/g, " ");
    if (node.previousSibling == null && node.parentElement != null && isLine2(node.parentElement, scroll) || node.previousSibling instanceof Element && isLine2(node.previousSibling, scroll)) {
      text = text.replace(/^ /, "");
    }
    if (node.nextSibling == null && node.parentElement != null && isLine2(node.parentElement, scroll) || node.nextSibling instanceof Element && isLine2(node.nextSibling, scroll)) {
      text = text.replace(/ $/, "");
    }
    text = text.replaceAll(" ", " ");
  }
  return delta.insert(text);
}

// node_modules/quill/modules/history.js
var History = class extends module_default {
  static DEFAULTS = {
    delay: 1e3,
    maxStack: 100,
    userOnly: false
  };
  lastRecorded = 0;
  ignoreChange = false;
  stack = {
    undo: [],
    redo: []
  };
  currentRange = null;
  constructor(quill, options) {
    super(quill, options);
    this.quill.on(Quill.events.EDITOR_CHANGE, (eventName, value, oldValue, source) => {
      if (eventName === Quill.events.SELECTION_CHANGE) {
        if (value && source !== Quill.sources.SILENT) {
          this.currentRange = value;
        }
      } else if (eventName === Quill.events.TEXT_CHANGE) {
        if (!this.ignoreChange) {
          if (!this.options.userOnly || source === Quill.sources.USER) {
            this.record(value, oldValue);
          } else {
            this.transform(value);
          }
        }
        this.currentRange = transformRange(this.currentRange, value);
      }
    });
    this.quill.keyboard.addBinding({
      key: "z",
      shortKey: true
    }, this.undo.bind(this));
    this.quill.keyboard.addBinding({
      key: ["z", "Z"],
      shortKey: true,
      shiftKey: true
    }, this.redo.bind(this));
    if (/Win/i.test(navigator.platform)) {
      this.quill.keyboard.addBinding({
        key: "y",
        shortKey: true
      }, this.redo.bind(this));
    }
    this.quill.root.addEventListener("beforeinput", (event) => {
      if (event.inputType === "historyUndo") {
        this.undo();
        event.preventDefault();
      } else if (event.inputType === "historyRedo") {
        this.redo();
        event.preventDefault();
      }
    });
  }
  change(source, dest) {
    if (this.stack[source].length === 0) return;
    const item = this.stack[source].pop();
    if (!item) return;
    const base = this.quill.getContents();
    const inverseDelta = item.delta.invert(base);
    this.stack[dest].push({
      delta: inverseDelta,
      range: transformRange(item.range, inverseDelta)
    });
    this.lastRecorded = 0;
    this.ignoreChange = true;
    this.quill.updateContents(item.delta, Quill.sources.USER);
    this.ignoreChange = false;
    this.restoreSelection(item);
  }
  clear() {
    this.stack = {
      undo: [],
      redo: []
    };
  }
  cutoff() {
    this.lastRecorded = 0;
  }
  record(changeDelta, oldDelta) {
    if (changeDelta.ops.length === 0) return;
    this.stack.redo = [];
    let undoDelta = changeDelta.invert(oldDelta);
    let undoRange = this.currentRange;
    const timestamp = Date.now();
    if (
      // @ts-expect-error Fix me later
      this.lastRecorded + this.options.delay > timestamp && this.stack.undo.length > 0
    ) {
      const item = this.stack.undo.pop();
      if (item) {
        undoDelta = undoDelta.compose(item.delta);
        undoRange = item.range;
      }
    } else {
      this.lastRecorded = timestamp;
    }
    if (undoDelta.length() === 0) return;
    this.stack.undo.push({
      delta: undoDelta,
      range: undoRange
    });
    if (this.stack.undo.length > this.options.maxStack) {
      this.stack.undo.shift();
    }
  }
  redo() {
    this.change("redo", "undo");
  }
  transform(delta) {
    transformStack(this.stack.undo, delta);
    transformStack(this.stack.redo, delta);
  }
  undo() {
    this.change("undo", "redo");
  }
  restoreSelection(stackItem) {
    if (stackItem.range) {
      this.quill.setSelection(stackItem.range, Quill.sources.USER);
    } else {
      const index = getLastChangeIndex(this.quill.scroll, stackItem.delta);
      this.quill.setSelection(index, Quill.sources.USER);
    }
  }
};
function transformStack(stack, delta) {
  let remoteDelta = delta;
  for (let i = stack.length - 1; i >= 0; i -= 1) {
    const oldItem = stack[i];
    stack[i] = {
      delta: remoteDelta.transform(oldItem.delta, true),
      range: oldItem.range && transformRange(oldItem.range, remoteDelta)
    };
    remoteDelta = oldItem.delta.transform(remoteDelta);
    if (stack[i].delta.length() === 0) {
      stack.splice(i, 1);
    }
  }
}
function endsWithNewlineChange(scroll, delta) {
  const lastOp = delta.ops[delta.ops.length - 1];
  if (lastOp == null) return false;
  if (lastOp.insert != null) {
    return typeof lastOp.insert === "string" && lastOp.insert.endsWith("\n");
  }
  if (lastOp.attributes != null) {
    return Object.keys(lastOp.attributes).some((attr) => {
      return scroll.query(attr, Scope.BLOCK) != null;
    });
  }
  return false;
}
function getLastChangeIndex(scroll, delta) {
  const deleteLength = delta.reduce((length, op) => {
    return length + (op.delete || 0);
  }, 0);
  let changeIndex = delta.length() - deleteLength;
  if (endsWithNewlineChange(scroll, delta)) {
    changeIndex -= 1;
  }
  return changeIndex;
}
function transformRange(range2, delta) {
  if (!range2) return range2;
  const start = delta.transformPosition(range2.index);
  const end = delta.transformPosition(range2.index + range2.length);
  return {
    index: start,
    length: end - start
  };
}

// node_modules/quill/modules/uploader.js
var import_quill_delta7 = __toESM(require_Delta(), 1);
var Uploader = class extends module_default {
  constructor(quill, options) {
    super(quill, options);
    quill.root.addEventListener("drop", (e) => {
      e.preventDefault();
      let native = null;
      if (document.caretRangeFromPoint) {
        native = document.caretRangeFromPoint(e.clientX, e.clientY);
      } else if (document.caretPositionFromPoint) {
        const position = document.caretPositionFromPoint(e.clientX, e.clientY);
        native = document.createRange();
        native.setStart(position.offsetNode, position.offset);
        native.setEnd(position.offsetNode, position.offset);
      }
      const normalized = native && quill.selection.normalizeNative(native);
      if (normalized) {
        const range2 = quill.selection.normalizedToRange(normalized);
        if (e.dataTransfer?.files) {
          this.upload(range2, e.dataTransfer.files);
        }
      }
    });
  }
  upload(range2, files) {
    const uploads = [];
    Array.from(files).forEach((file) => {
      if (file && this.options.mimetypes?.includes(file.type)) {
        uploads.push(file);
      }
    });
    if (uploads.length > 0) {
      this.options.handler.call(this, range2, uploads);
    }
  }
};
Uploader.DEFAULTS = {
  mimetypes: ["image/png", "image/jpeg"],
  handler(range2, files) {
    if (!this.quill.scroll.query("image")) {
      return;
    }
    const promises = files.map((file) => {
      return new Promise((resolve) => {
        const reader = new FileReader();
        reader.onload = () => {
          resolve(reader.result);
        };
        reader.readAsDataURL(file);
      });
    });
    Promise.all(promises).then((images) => {
      const update2 = images.reduce((delta, image) => {
        return delta.insert({
          image
        });
      }, new import_quill_delta7.default().retain(range2.index).delete(range2.length));
      this.quill.updateContents(update2, emitter_default.sources.USER);
      this.quill.setSelection(range2.index + images.length, emitter_default.sources.SILENT);
    });
  }
};
var uploader_default = Uploader;

// node_modules/quill/core.js
var import_quill_delta9 = __toESM(require_Delta(), 1);

// node_modules/quill/modules/input.js
var import_quill_delta8 = __toESM(require_Delta(), 1);
var INSERT_TYPES = ["insertText", "insertReplacementText"];
var Input = class extends module_default {
  constructor(quill, options) {
    super(quill, options);
    quill.root.addEventListener("beforeinput", (event) => {
      this.handleBeforeInput(event);
    });
    if (!/Android/i.test(navigator.userAgent)) {
      quill.on(Quill.events.COMPOSITION_BEFORE_START, () => {
        this.handleCompositionStart();
      });
    }
  }
  deleteRange(range2) {
    deleteRange({
      range: range2,
      quill: this.quill
    });
  }
  replaceText(range2) {
    let text = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : "";
    if (range2.length === 0) return false;
    if (text) {
      const formats = this.quill.getFormat(range2.index, 1);
      this.deleteRange(range2);
      this.quill.updateContents(new import_quill_delta8.default().retain(range2.index).insert(text, formats), Quill.sources.USER);
    } else {
      this.deleteRange(range2);
    }
    this.quill.setSelection(range2.index + text.length, 0, Quill.sources.SILENT);
    return true;
  }
  handleBeforeInput(event) {
    if (this.quill.composition.isComposing || event.defaultPrevented || !INSERT_TYPES.includes(event.inputType)) {
      return;
    }
    const staticRange = event.getTargetRanges ? event.getTargetRanges()[0] : null;
    if (!staticRange || staticRange.collapsed === true) {
      return;
    }
    const text = getPlainTextFromInputEvent(event);
    if (text == null) {
      return;
    }
    const normalized = this.quill.selection.normalizeNative(staticRange);
    const range2 = normalized ? this.quill.selection.normalizedToRange(normalized) : null;
    if (range2 && this.replaceText(range2, text)) {
      event.preventDefault();
    }
  }
  handleCompositionStart() {
    const range2 = this.quill.getSelection();
    if (range2) {
      this.replaceText(range2);
    }
  }
};
function getPlainTextFromInputEvent(event) {
  if (typeof event.data === "string") {
    return event.data;
  }
  if (event.dataTransfer?.types.includes("text/plain")) {
    return event.dataTransfer.getData("text/plain");
  }
  return null;
}
var input_default = Input;

// node_modules/quill/modules/uiNode.js
var isMac = /Mac/i.test(navigator.platform);
var TTL_FOR_VALID_SELECTION_CHANGE = 100;
var canMoveCaretBeforeUINode = (event) => {
  if (event.key === "ArrowLeft" || event.key === "ArrowRight" || // RTL scripts or moving from the end of the previous line
  event.key === "ArrowUp" || event.key === "ArrowDown" || event.key === "Home") {
    return true;
  }
  if (isMac && event.key === "a" && event.ctrlKey === true) {
    return true;
  }
  return false;
};
var UINode = class extends module_default {
  isListening = false;
  selectionChangeDeadline = 0;
  constructor(quill, options) {
    super(quill, options);
    this.handleArrowKeys();
    this.handleNavigationShortcuts();
  }
  handleArrowKeys() {
    this.quill.keyboard.addBinding({
      key: ["ArrowLeft", "ArrowRight"],
      offset: 0,
      shiftKey: null,
      handler(range2, _ref) {
        let {
          line,
          event
        } = _ref;
        if (!(line instanceof ParentBlot$1) || !line.uiNode) {
          return true;
        }
        const isRTL = getComputedStyle(line.domNode)["direction"] === "rtl";
        if (isRTL && event.key !== "ArrowRight" || !isRTL && event.key !== "ArrowLeft") {
          return true;
        }
        this.quill.setSelection(range2.index - 1, range2.length + (event.shiftKey ? 1 : 0), Quill.sources.USER);
        return false;
      }
    });
  }
  handleNavigationShortcuts() {
    this.quill.root.addEventListener("keydown", (event) => {
      if (!event.defaultPrevented && canMoveCaretBeforeUINode(event)) {
        this.ensureListeningToSelectionChange();
      }
    });
  }
  /**
   * We only listen to the `selectionchange` event when
   * there is an intention of moving the caret to the beginning using shortcuts.
   * This is primarily implemented to prevent infinite loops, as we are changing
   * the selection within the handler of a `selectionchange` event.
   */
  ensureListeningToSelectionChange() {
    this.selectionChangeDeadline = Date.now() + TTL_FOR_VALID_SELECTION_CHANGE;
    if (this.isListening) return;
    this.isListening = true;
    const listener = () => {
      this.isListening = false;
      if (Date.now() <= this.selectionChangeDeadline) {
        this.handleSelectionChange();
      }
    };
    document.addEventListener("selectionchange", listener, {
      once: true
    });
  }
  handleSelectionChange() {
    const selection = document.getSelection();
    if (!selection) return;
    const range2 = selection.getRangeAt(0);
    if (range2.collapsed !== true || range2.startOffset !== 0) return;
    const line = this.quill.scroll.find(range2.startContainer);
    if (!(line instanceof ParentBlot$1) || !line.uiNode) return;
    const newRange = document.createRange();
    newRange.setStartAfter(line.uiNode);
    newRange.setEndAfter(line.uiNode);
    selection.removeAllRanges();
    selection.addRange(newRange);
  }
};
var uiNode_default = UINode;

// node_modules/quill/core.js
Quill.register({
  "blots/block": Block,
  "blots/block/embed": BlockEmbed,
  "blots/break": break_default,
  "blots/container": container_default,
  "blots/cursor": cursor_default,
  "blots/embed": embed_default,
  "blots/inline": inline_default,
  "blots/scroll": scroll_default,
  "blots/text": Text2,
  "modules/clipboard": Clipboard,
  "modules/history": History,
  "modules/keyboard": Keyboard,
  "modules/uploader": uploader_default,
  "modules/input": input_default,
  "modules/uiNode": uiNode_default
});
var core_default = Quill;

// node_modules/quill/formats/indent.js
var IndentAttributor = class extends ClassAttributor$1 {
  add(node, value) {
    let normalizedValue = 0;
    if (value === "+1" || value === "-1") {
      const indent = this.value(node) || 0;
      normalizedValue = value === "+1" ? indent + 1 : indent - 1;
    } else if (typeof value === "number") {
      normalizedValue = value;
    }
    if (normalizedValue === 0) {
      this.remove(node);
      return true;
    }
    return super.add(node, normalizedValue.toString());
  }
  canAdd(node, value) {
    return super.canAdd(node, value) || super.canAdd(node, parseInt(value, 10));
  }
  value(node) {
    return parseInt(super.value(node), 10) || void 0;
  }
};
var IndentClass = new IndentAttributor("indent", "ql-indent", {
  scope: Scope.BLOCK,
  // @ts-expect-error
  whitelist: [1, 2, 3, 4, 5, 6, 7, 8]
});
var indent_default = IndentClass;

// node_modules/quill/formats/blockquote.js
var Blockquote = class extends Block {
  static blotName = "blockquote";
  static tagName = "blockquote";
};
var blockquote_default = Blockquote;

// node_modules/quill/formats/header.js
var Header = class extends Block {
  static blotName = "header";
  static tagName = ["H1", "H2", "H3", "H4", "H5", "H6"];
  static formats(domNode) {
    return this.tagName.indexOf(domNode.tagName) + 1;
  }
};
var header_default = Header;

// node_modules/quill/formats/list.js
var ListContainer = class extends container_default {
};
ListContainer.blotName = "list-container";
ListContainer.tagName = "OL";
var ListItem = class extends Block {
  static create(value) {
    const node = super.create();
    node.setAttribute("data-list", value);
    return node;
  }
  static formats(domNode) {
    return domNode.getAttribute("data-list") || void 0;
  }
  static register() {
    Quill.register(ListContainer);
  }
  constructor(scroll, domNode) {
    super(scroll, domNode);
    const ui = domNode.ownerDocument.createElement("span");
    const listEventHandler = (e) => {
      if (!scroll.isEnabled()) return;
      const format = this.statics.formats(domNode, scroll);
      if (format === "checked") {
        this.format("list", "unchecked");
        e.preventDefault();
      } else if (format === "unchecked") {
        this.format("list", "checked");
        e.preventDefault();
      }
    };
    ui.addEventListener("mousedown", listEventHandler);
    ui.addEventListener("touchstart", listEventHandler);
    this.attachUI(ui);
  }
  format(name, value) {
    if (name === this.statics.blotName && value) {
      this.domNode.setAttribute("data-list", value);
    } else {
      super.format(name, value);
    }
  }
};
ListItem.blotName = "list";
ListItem.tagName = "LI";
ListContainer.allowedChildren = [ListItem];
ListItem.requiredContainer = ListContainer;

// node_modules/quill/formats/bold.js
var Bold = class extends inline_default {
  static blotName = "bold";
  static tagName = ["STRONG", "B"];
  static create() {
    return super.create();
  }
  static formats() {
    return true;
  }
  optimize(context) {
    super.optimize(context);
    if (this.domNode.tagName !== this.statics.tagName[0]) {
      this.replaceWith(this.statics.blotName);
    }
  }
};
var bold_default = Bold;

// node_modules/quill/formats/italic.js
var Italic = class extends bold_default {
  static blotName = "italic";
  static tagName = ["EM", "I"];
};
var italic_default = Italic;

// node_modules/quill/formats/link.js
var Link = class extends inline_default {
  static blotName = "link";
  static tagName = "A";
  static SANITIZED_URL = "about:blank";
  static PROTOCOL_WHITELIST = ["http", "https", "mailto", "tel", "sms"];
  static create(value) {
    const node = super.create(value);
    node.setAttribute("href", this.sanitize(value));
    node.setAttribute("rel", "noopener noreferrer");
    node.setAttribute("target", "_blank");
    return node;
  }
  static formats(domNode) {
    return domNode.getAttribute("href");
  }
  static sanitize(url) {
    return sanitize(url, this.PROTOCOL_WHITELIST) ? url : this.SANITIZED_URL;
  }
  format(name, value) {
    if (name !== this.statics.blotName || !value) {
      super.format(name, value);
    } else {
      this.domNode.setAttribute("href", this.constructor.sanitize(value));
    }
  }
};
function sanitize(url, protocols) {
  const anchor = document.createElement("a");
  anchor.href = url;
  const protocol = anchor.href.slice(0, anchor.href.indexOf(":"));
  return protocols.indexOf(protocol) > -1;
}

// node_modules/quill/formats/script.js
var Script = class extends inline_default {
  static blotName = "script";
  static tagName = ["SUB", "SUP"];
  static create(value) {
    if (value === "super") {
      return document.createElement("sup");
    }
    if (value === "sub") {
      return document.createElement("sub");
    }
    return super.create(value);
  }
  static formats(domNode) {
    if (domNode.tagName === "SUB") return "sub";
    if (domNode.tagName === "SUP") return "super";
    return void 0;
  }
};
var script_default = Script;

// node_modules/quill/formats/strike.js
var Strike = class extends bold_default {
  static blotName = "strike";
  static tagName = ["S", "STRIKE"];
};
var strike_default = Strike;

// node_modules/quill/formats/underline.js
var Underline = class extends inline_default {
  static blotName = "underline";
  static tagName = "U";
};
var underline_default = Underline;

// node_modules/quill/formats/formula.js
var Formula = class extends embed_default {
  static blotName = "formula";
  static className = "ql-formula";
  static tagName = "SPAN";
  static create(value) {
    if (window.katex == null) {
      throw new Error("Formula module requires KaTeX.");
    }
    const node = super.create(value);
    if (typeof value === "string") {
      window.katex.render(value, node, {
        throwOnError: false,
        errorColor: "#f00"
      });
      node.setAttribute("data-value", value);
    }
    return node;
  }
  static value(domNode) {
    return domNode.getAttribute("data-value");
  }
  html() {
    const {
      formula
    } = this.value();
    return `<span>${formula}</span>`;
  }
};
var formula_default = Formula;

// node_modules/quill/formats/image.js
var ATTRIBUTES = ["alt", "height", "width"];
var Image = class extends EmbedBlot$1 {
  static blotName = "image";
  static tagName = "IMG";
  static create(value) {
    const node = super.create(value);
    if (typeof value === "string") {
      node.setAttribute("src", this.sanitize(value));
    }
    return node;
  }
  static formats(domNode) {
    return ATTRIBUTES.reduce((formats, attribute) => {
      if (domNode.hasAttribute(attribute)) {
        formats[attribute] = domNode.getAttribute(attribute);
      }
      return formats;
    }, {});
  }
  static match(url) {
    return /\.(jpe?g|gif|png)$/.test(url) || /^data:image\/.+;base64/.test(url);
  }
  static sanitize(url) {
    return sanitize(url, ["http", "https", "data"]) ? url : "//:0";
  }
  static value(domNode) {
    return domNode.getAttribute("src");
  }
  format(name, value) {
    if (ATTRIBUTES.indexOf(name) > -1) {
      if (value) {
        this.domNode.setAttribute(name, value);
      } else {
        this.domNode.removeAttribute(name);
      }
    } else {
      super.format(name, value);
    }
  }
};
var image_default = Image;

// node_modules/quill/formats/video.js
var ATTRIBUTES2 = ["height", "width"];
var Video = class extends BlockEmbed {
  static blotName = "video";
  static className = "ql-video";
  static tagName = "IFRAME";
  static create(value) {
    const node = super.create(value);
    node.setAttribute("frameborder", "0");
    node.setAttribute("allowfullscreen", "true");
    node.setAttribute("src", this.sanitize(value));
    return node;
  }
  static formats(domNode) {
    return ATTRIBUTES2.reduce((formats, attribute) => {
      if (domNode.hasAttribute(attribute)) {
        formats[attribute] = domNode.getAttribute(attribute);
      }
      return formats;
    }, {});
  }
  static sanitize(url) {
    return Link.sanitize(url);
  }
  static value(domNode) {
    return domNode.getAttribute("src");
  }
  format(name, value) {
    if (ATTRIBUTES2.indexOf(name) > -1) {
      if (value) {
        this.domNode.setAttribute(name, value);
      } else {
        this.domNode.removeAttribute(name);
      }
    } else {
      super.format(name, value);
    }
  }
  html() {
    const {
      video
    } = this.value();
    return `<a href="${video}">${video}</a>`;
  }
};
var video_default = Video;

// node_modules/quill/modules/syntax.js
var import_quill_delta10 = __toESM(require_Delta(), 1);
var TokenAttributor = new ClassAttributor$1("code-token", "hljs", {
  scope: Scope.INLINE
});
var CodeToken = class _CodeToken extends inline_default {
  static formats(node, scroll) {
    while (node != null && node !== scroll.domNode) {
      if (node.classList && node.classList.contains(CodeBlock.className)) {
        return super.formats(node, scroll);
      }
      node = node.parentNode;
    }
    return void 0;
  }
  constructor(scroll, domNode, value) {
    super(scroll, domNode, value);
    TokenAttributor.add(this.domNode, value);
  }
  format(format, value) {
    if (format !== _CodeToken.blotName) {
      super.format(format, value);
    } else if (value) {
      TokenAttributor.add(this.domNode, value);
    } else {
      TokenAttributor.remove(this.domNode);
      this.domNode.classList.remove(this.statics.className);
    }
  }
  optimize() {
    super.optimize(...arguments);
    if (!TokenAttributor.value(this.domNode)) {
      this.unwrap();
    }
  }
};
CodeToken.blotName = "code-token";
CodeToken.className = "ql-token";
var SyntaxCodeBlock = class extends CodeBlock {
  static create(value) {
    const domNode = super.create(value);
    if (typeof value === "string") {
      domNode.setAttribute("data-language", value);
    }
    return domNode;
  }
  static formats(domNode) {
    return domNode.getAttribute("data-language") || "plain";
  }
  static register() {
  }
  // Syntax module will register
  format(name, value) {
    if (name === this.statics.blotName && value) {
      this.domNode.setAttribute("data-language", value);
    } else {
      super.format(name, value);
    }
  }
  replaceWith(name, value) {
    this.formatAt(0, this.length(), CodeToken.blotName, false);
    return super.replaceWith(name, value);
  }
};
var SyntaxCodeBlockContainer = class extends CodeBlockContainer {
  attach() {
    super.attach();
    this.forceNext = false;
    this.scroll.emitMount(this);
  }
  format(name, value) {
    if (name === SyntaxCodeBlock.blotName) {
      this.forceNext = true;
      this.children.forEach((child) => {
        child.format(name, value);
      });
    }
  }
  formatAt(index, length, name, value) {
    if (name === SyntaxCodeBlock.blotName) {
      this.forceNext = true;
    }
    super.formatAt(index, length, name, value);
  }
  highlight(highlight2) {
    let forced = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : false;
    if (this.children.head == null) return;
    const nodes = Array.from(this.domNode.childNodes).filter((node) => node !== this.uiNode);
    const text = `${nodes.map((node) => node.textContent).join("\n")}
`;
    const language = SyntaxCodeBlock.formats(this.children.head.domNode);
    if (forced || this.forceNext || this.cachedText !== text) {
      if (text.trim().length > 0 || this.cachedText == null) {
        const oldDelta = this.children.reduce((delta2, child) => {
          return delta2.concat(blockDelta(child, false));
        }, new import_quill_delta10.default());
        const delta = highlight2(text, language);
        oldDelta.diff(delta).reduce((index, _ref) => {
          let {
            retain,
            attributes
          } = _ref;
          if (!retain) return index;
          if (attributes) {
            Object.keys(attributes).forEach((format) => {
              if ([SyntaxCodeBlock.blotName, CodeToken.blotName].includes(format)) {
                this.formatAt(index, retain, format, attributes[format]);
              }
            });
          }
          return index + retain;
        }, 0);
      }
      this.cachedText = text;
      this.forceNext = false;
    }
  }
  html(index, length) {
    const [codeBlock] = this.children.find(index);
    const language = codeBlock ? SyntaxCodeBlock.formats(codeBlock.domNode) : "plain";
    return `<pre data-language="${language}">
${escapeText(this.code(index, length))}
</pre>`;
  }
  optimize(context) {
    super.optimize(context);
    if (this.parent != null && this.children.head != null && this.uiNode != null) {
      const language = SyntaxCodeBlock.formats(this.children.head.domNode);
      if (language !== this.uiNode.value) {
        this.uiNode.value = language;
      }
    }
  }
};
SyntaxCodeBlockContainer.allowedChildren = [SyntaxCodeBlock];
SyntaxCodeBlock.requiredContainer = SyntaxCodeBlockContainer;
SyntaxCodeBlock.allowedChildren = [CodeToken, cursor_default, Text2, break_default];
var highlight = (lib, language, text) => {
  if (typeof lib.versionString === "string") {
    const majorVersion = lib.versionString.split(".")[0];
    if (parseInt(majorVersion, 10) >= 11) {
      return lib.highlight(text, {
        language
      }).value;
    }
  }
  return lib.highlight(language, text).value;
};
var Syntax = class extends module_default {
  static register() {
    Quill.register(CodeToken, true);
    Quill.register(SyntaxCodeBlock, true);
    Quill.register(SyntaxCodeBlockContainer, true);
  }
  constructor(quill, options) {
    super(quill, options);
    if (this.options.hljs == null) {
      throw new Error("Syntax module requires highlight.js. Please include the library on the page before Quill.");
    }
    this.languages = this.options.languages.reduce((memo, _ref2) => {
      let {
        key
      } = _ref2;
      memo[key] = true;
      return memo;
    }, {});
    this.highlightBlot = this.highlightBlot.bind(this);
    this.initListener();
    this.initTimer();
  }
  initListener() {
    this.quill.on(Quill.events.SCROLL_BLOT_MOUNT, (blot) => {
      if (!(blot instanceof SyntaxCodeBlockContainer)) return;
      const select = this.quill.root.ownerDocument.createElement("select");
      this.options.languages.forEach((_ref3) => {
        let {
          key,
          label
        } = _ref3;
        const option = select.ownerDocument.createElement("option");
        option.textContent = label;
        option.setAttribute("value", key);
        select.appendChild(option);
      });
      select.addEventListener("change", () => {
        blot.format(SyntaxCodeBlock.blotName, select.value);
        this.quill.root.focus();
        this.highlight(blot, true);
      });
      if (blot.uiNode == null) {
        blot.attachUI(select);
        if (blot.children.head) {
          select.value = SyntaxCodeBlock.formats(blot.children.head.domNode);
        }
      }
    });
  }
  initTimer() {
    let timer = null;
    this.quill.on(Quill.events.SCROLL_OPTIMIZE, () => {
      if (timer) {
        clearTimeout(timer);
      }
      timer = setTimeout(() => {
        this.highlight();
        timer = null;
      }, this.options.interval);
    });
  }
  highlight() {
    let blot = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : null;
    let force = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : false;
    if (this.quill.selection.composing) return;
    this.quill.update(Quill.sources.USER);
    const range2 = this.quill.getSelection();
    const blots = blot == null ? this.quill.scroll.descendants(SyntaxCodeBlockContainer) : [blot];
    blots.forEach((container) => {
      container.highlight(this.highlightBlot, force);
    });
    this.quill.update(Quill.sources.SILENT);
    if (range2 != null) {
      this.quill.setSelection(range2, Quill.sources.SILENT);
    }
  }
  highlightBlot(text) {
    let language = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : "plain";
    language = this.languages[language] ? language : "plain";
    if (language === "plain") {
      return escapeText(text).split("\n").reduce((delta, line, i) => {
        if (i !== 0) {
          delta.insert("\n", {
            [CodeBlock.blotName]: language
          });
        }
        return delta.insert(line);
      }, new import_quill_delta10.default());
    }
    const container = this.quill.root.ownerDocument.createElement("div");
    container.classList.add(CodeBlock.className);
    container.innerHTML = highlight(this.options.hljs, language, text);
    return traverse(this.quill.scroll, container, [(node, delta) => {
      const value = TokenAttributor.value(node);
      if (value) {
        return delta.compose(new import_quill_delta10.default().retain(delta.length(), {
          [CodeToken.blotName]: value
        }));
      }
      return delta;
    }], [(node, delta) => {
      return node.data.split("\n").reduce((memo, nodeText, i) => {
        if (i !== 0) memo.insert("\n", {
          [CodeBlock.blotName]: language
        });
        return memo.insert(nodeText);
      }, delta);
    }], /* @__PURE__ */ new WeakMap());
  }
};
Syntax.DEFAULTS = {
  hljs: (() => {
    return window.hljs;
  })(),
  interval: 1e3,
  languages: [{
    key: "plain",
    label: "Plain"
  }, {
    key: "bash",
    label: "Bash"
  }, {
    key: "cpp",
    label: "C++"
  }, {
    key: "cs",
    label: "C#"
  }, {
    key: "css",
    label: "CSS"
  }, {
    key: "diff",
    label: "Diff"
  }, {
    key: "xml",
    label: "HTML/XML"
  }, {
    key: "java",
    label: "Java"
  }, {
    key: "javascript",
    label: "JavaScript"
  }, {
    key: "markdown",
    label: "Markdown"
  }, {
    key: "php",
    label: "PHP"
  }, {
    key: "python",
    label: "Python"
  }, {
    key: "ruby",
    label: "Ruby"
  }, {
    key: "sql",
    label: "SQL"
  }]
};

// node_modules/quill/modules/table.js
var import_quill_delta11 = __toESM(require_Delta(), 1);

// node_modules/quill/formats/table.js
var TableCell = class _TableCell extends Block {
  static blotName = "table";
  static tagName = "TD";
  static create(value) {
    const node = super.create();
    if (value) {
      node.setAttribute("data-row", value);
    } else {
      node.setAttribute("data-row", tableId());
    }
    return node;
  }
  static formats(domNode) {
    if (domNode.hasAttribute("data-row")) {
      return domNode.getAttribute("data-row");
    }
    return void 0;
  }
  cellOffset() {
    if (this.parent) {
      return this.parent.children.indexOf(this);
    }
    return -1;
  }
  format(name, value) {
    if (name === _TableCell.blotName && value) {
      this.domNode.setAttribute("data-row", value);
    } else {
      super.format(name, value);
    }
  }
  row() {
    return this.parent;
  }
  rowOffset() {
    if (this.row()) {
      return this.row().rowOffset();
    }
    return -1;
  }
  table() {
    return this.row() && this.row().table();
  }
};
var TableRow = class extends container_default {
  static blotName = "table-row";
  static tagName = "TR";
  checkMerge() {
    if (super.checkMerge() && this.next.children.head != null) {
      const thisHead = this.children.head.formats();
      const thisTail = this.children.tail.formats();
      const nextHead = this.next.children.head.formats();
      const nextTail = this.next.children.tail.formats();
      return thisHead.table === thisTail.table && thisHead.table === nextHead.table && thisHead.table === nextTail.table;
    }
    return false;
  }
  optimize(context) {
    super.optimize(context);
    this.children.forEach((child) => {
      if (child.next == null) return;
      const childFormats = child.formats();
      const nextFormats = child.next.formats();
      if (childFormats.table !== nextFormats.table) {
        const next = this.splitAfter(child);
        if (next) {
          next.optimize();
        }
        if (this.prev) {
          this.prev.optimize();
        }
      }
    });
  }
  rowOffset() {
    if (this.parent) {
      return this.parent.children.indexOf(this);
    }
    return -1;
  }
  table() {
    return this.parent && this.parent.parent;
  }
};
var TableBody = class extends container_default {
  static blotName = "table-body";
  static tagName = "TBODY";
};
var TableContainer = class extends container_default {
  static blotName = "table-container";
  static tagName = "TABLE";
  balanceCells() {
    const rows = this.descendants(TableRow);
    const maxColumns = rows.reduce((max2, row) => {
      return Math.max(row.children.length, max2);
    }, 0);
    rows.forEach((row) => {
      new Array(maxColumns - row.children.length).fill(0).forEach(() => {
        let value;
        if (row.children.head != null) {
          value = TableCell.formats(row.children.head.domNode);
        }
        const blot = this.scroll.create(TableCell.blotName, value);
        row.appendChild(blot);
        blot.optimize();
      });
    });
  }
  cells(column) {
    return this.rows().map((row) => row.children.at(column));
  }
  deleteColumn(index) {
    const [body] = this.descendant(TableBody);
    if (body == null || body.children.head == null) return;
    body.children.forEach((row) => {
      const cell = row.children.at(index);
      if (cell != null) {
        cell.remove();
      }
    });
  }
  insertColumn(index) {
    const [body] = this.descendant(TableBody);
    if (body == null || body.children.head == null) return;
    body.children.forEach((row) => {
      const ref = row.children.at(index);
      const value = TableCell.formats(row.children.head.domNode);
      const cell = this.scroll.create(TableCell.blotName, value);
      row.insertBefore(cell, ref);
    });
  }
  insertRow(index) {
    const [body] = this.descendant(TableBody);
    if (body == null || body.children.head == null) return;
    const id = tableId();
    const row = this.scroll.create(TableRow.blotName);
    body.children.head.children.forEach(() => {
      const cell = this.scroll.create(TableCell.blotName, id);
      row.appendChild(cell);
    });
    const ref = body.children.at(index);
    body.insertBefore(row, ref);
  }
  rows() {
    const body = this.children.head;
    if (body == null) return [];
    return body.children.map((row) => row);
  }
};
TableContainer.allowedChildren = [TableBody];
TableBody.requiredContainer = TableContainer;
TableBody.allowedChildren = [TableRow];
TableRow.requiredContainer = TableBody;
TableRow.allowedChildren = [TableCell];
TableCell.requiredContainer = TableRow;
function tableId() {
  const id = Math.random().toString(36).slice(2, 6);
  return `row-${id}`;
}

// node_modules/quill/modules/table.js
var Table = class extends module_default {
  static register() {
    Quill.register(TableCell);
    Quill.register(TableRow);
    Quill.register(TableBody);
    Quill.register(TableContainer);
  }
  constructor() {
    super(...arguments);
    this.listenBalanceCells();
  }
  balanceTables() {
    this.quill.scroll.descendants(TableContainer).forEach((table) => {
      table.balanceCells();
    });
  }
  deleteColumn() {
    const [table, , cell] = this.getTable();
    if (cell == null) return;
    table.deleteColumn(cell.cellOffset());
    this.quill.update(Quill.sources.USER);
  }
  deleteRow() {
    const [, row] = this.getTable();
    if (row == null) return;
    row.remove();
    this.quill.update(Quill.sources.USER);
  }
  deleteTable() {
    const [table] = this.getTable();
    if (table == null) return;
    const offset = table.offset();
    table.remove();
    this.quill.update(Quill.sources.USER);
    this.quill.setSelection(offset, Quill.sources.SILENT);
  }
  getTable() {
    let range2 = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : this.quill.getSelection();
    if (range2 == null) return [null, null, null, -1];
    const [cell, offset] = this.quill.getLine(range2.index);
    if (cell == null || cell.statics.blotName !== TableCell.blotName) {
      return [null, null, null, -1];
    }
    const row = cell.parent;
    const table = row.parent.parent;
    return [table, row, cell, offset];
  }
  insertColumn(offset) {
    const range2 = this.quill.getSelection();
    if (!range2) return;
    const [table, row, cell] = this.getTable(range2);
    if (cell == null) return;
    const column = cell.cellOffset();
    table.insertColumn(column + offset);
    this.quill.update(Quill.sources.USER);
    let shift = row.rowOffset();
    if (offset === 0) {
      shift += 1;
    }
    this.quill.setSelection(range2.index + shift, range2.length, Quill.sources.SILENT);
  }
  insertColumnLeft() {
    this.insertColumn(0);
  }
  insertColumnRight() {
    this.insertColumn(1);
  }
  insertRow(offset) {
    const range2 = this.quill.getSelection();
    if (!range2) return;
    const [table, row, cell] = this.getTable(range2);
    if (cell == null) return;
    const index = row.rowOffset();
    table.insertRow(index + offset);
    this.quill.update(Quill.sources.USER);
    if (offset > 0) {
      this.quill.setSelection(range2, Quill.sources.SILENT);
    } else {
      this.quill.setSelection(range2.index + row.children.length, range2.length, Quill.sources.SILENT);
    }
  }
  insertRowAbove() {
    this.insertRow(0);
  }
  insertRowBelow() {
    this.insertRow(1);
  }
  insertTable(rows, columns) {
    const range2 = this.quill.getSelection();
    if (range2 == null) return;
    const delta = new Array(rows).fill(0).reduce((memo) => {
      const text = new Array(columns).fill("\n").join("");
      return memo.insert(text, {
        table: tableId()
      });
    }, new import_quill_delta11.default().retain(range2.index));
    this.quill.updateContents(delta, Quill.sources.USER);
    this.quill.setSelection(range2.index, Quill.sources.SILENT);
    this.balanceTables();
  }
  listenBalanceCells() {
    this.quill.on(Quill.events.SCROLL_OPTIMIZE, (mutations) => {
      mutations.some((mutation) => {
        if (["TD", "TR", "TBODY", "TABLE"].includes(mutation.target.tagName)) {
          this.quill.once(Quill.events.TEXT_CHANGE, (delta, old, source) => {
            if (source !== Quill.sources.USER) return;
            this.balanceTables();
          });
          return true;
        }
        return false;
      });
    });
  }
};
var table_default = Table;

// node_modules/quill/modules/toolbar.js
var import_quill_delta12 = __toESM(require_Delta(), 1);
var debug7 = logger_default("quill:toolbar");
var Toolbar = class extends module_default {
  constructor(quill, options) {
    super(quill, options);
    if (Array.isArray(this.options.container)) {
      const container = document.createElement("div");
      container.setAttribute("role", "toolbar");
      addControls(container, this.options.container);
      quill.container?.parentNode?.insertBefore(container, quill.container);
      this.container = container;
    } else if (typeof this.options.container === "string") {
      this.container = document.querySelector(this.options.container);
    } else {
      this.container = this.options.container;
    }
    if (!(this.container instanceof HTMLElement)) {
      debug7.error("Container required for toolbar", this.options);
      return;
    }
    this.container.classList.add("ql-toolbar");
    this.controls = [];
    this.handlers = {};
    if (this.options.handlers) {
      Object.keys(this.options.handlers).forEach((format) => {
        const handler = this.options.handlers?.[format];
        if (handler) {
          this.addHandler(format, handler);
        }
      });
    }
    Array.from(this.container.querySelectorAll("button, select")).forEach((input) => {
      this.attach(input);
    });
    this.quill.on(Quill.events.EDITOR_CHANGE, () => {
      const [range2] = this.quill.selection.getRange();
      this.update(range2);
    });
  }
  addHandler(format, handler) {
    this.handlers[format] = handler;
  }
  attach(input) {
    let format = Array.from(input.classList).find((className) => {
      return className.indexOf("ql-") === 0;
    });
    if (!format) return;
    format = format.slice("ql-".length);
    if (input.tagName === "BUTTON") {
      input.setAttribute("type", "button");
    }
    if (this.handlers[format] == null && this.quill.scroll.query(format) == null) {
      debug7.warn("ignoring attaching to nonexistent format", format, input);
      return;
    }
    const eventName = input.tagName === "SELECT" ? "change" : "click";
    input.addEventListener(eventName, (e) => {
      let value;
      if (input.tagName === "SELECT") {
        if (input.selectedIndex < 0) return;
        const selected = input.options[input.selectedIndex];
        if (selected.hasAttribute("selected")) {
          value = false;
        } else {
          value = selected.value || false;
        }
      } else {
        if (input.classList.contains("ql-active")) {
          value = false;
        } else {
          value = input.value || !input.hasAttribute("value");
        }
        e.preventDefault();
      }
      this.quill.focus();
      const [range2] = this.quill.selection.getRange();
      if (this.handlers[format] != null) {
        this.handlers[format].call(this, value);
      } else if (
        // @ts-expect-error
        this.quill.scroll.query(format).prototype instanceof EmbedBlot$1
      ) {
        value = prompt(`Enter ${format}`);
        if (!value) return;
        this.quill.updateContents(new import_quill_delta12.default().retain(range2.index).delete(range2.length).insert({
          [format]: value
        }), Quill.sources.USER);
      } else {
        this.quill.format(format, value, Quill.sources.USER);
      }
      this.update(range2);
    });
    this.controls.push([format, input]);
  }
  update(range2) {
    const formats = range2 == null ? {} : this.quill.getFormat(range2);
    this.controls.forEach((pair) => {
      const [format, input] = pair;
      if (input.tagName === "SELECT") {
        let option = null;
        if (range2 == null) {
          option = null;
        } else if (formats[format] == null) {
          option = input.querySelector("option[selected]");
        } else if (!Array.isArray(formats[format])) {
          let value = formats[format];
          if (typeof value === "string") {
            value = value.replace(/"/g, '\\"');
          }
          option = input.querySelector(`option[value="${value}"]`);
        }
        if (option == null) {
          input.value = "";
          input.selectedIndex = -1;
        } else {
          option.selected = true;
        }
      } else if (range2 == null) {
        input.classList.remove("ql-active");
        input.setAttribute("aria-pressed", "false");
      } else if (input.hasAttribute("value")) {
        const value = formats[format];
        const isActive = value === input.getAttribute("value") || value != null && value.toString() === input.getAttribute("value") || value == null && !input.getAttribute("value");
        input.classList.toggle("ql-active", isActive);
        input.setAttribute("aria-pressed", isActive.toString());
      } else {
        const isActive = formats[format] != null;
        input.classList.toggle("ql-active", isActive);
        input.setAttribute("aria-pressed", isActive.toString());
      }
    });
  }
};
Toolbar.DEFAULTS = {};
function addButton(container, format, value) {
  const input = document.createElement("button");
  input.setAttribute("type", "button");
  input.classList.add(`ql-${format}`);
  input.setAttribute("aria-pressed", "false");
  if (value != null) {
    input.value = value;
    input.setAttribute("aria-label", `${format}: ${value}`);
  } else {
    input.setAttribute("aria-label", format);
  }
  container.appendChild(input);
}
function addControls(container, groups) {
  if (!Array.isArray(groups[0])) {
    groups = [groups];
  }
  groups.forEach((controls) => {
    const group = document.createElement("span");
    group.classList.add("ql-formats");
    controls.forEach((control) => {
      if (typeof control === "string") {
        addButton(group, control);
      } else {
        const format = Object.keys(control)[0];
        const value = control[format];
        if (Array.isArray(value)) {
          addSelect(group, format, value);
        } else {
          addButton(group, format, value);
        }
      }
    });
    container.appendChild(group);
  });
}
function addSelect(container, format, values2) {
  const input = document.createElement("select");
  input.classList.add(`ql-${format}`);
  values2.forEach((value) => {
    const option = document.createElement("option");
    if (value !== false) {
      option.setAttribute("value", String(value));
    } else {
      option.setAttribute("selected", "selected");
    }
    input.appendChild(option);
  });
  container.appendChild(input);
}
Toolbar.DEFAULTS = {
  container: null,
  handlers: {
    clean() {
      const range2 = this.quill.getSelection();
      if (range2 == null) return;
      if (range2.length === 0) {
        const formats = this.quill.getFormat();
        Object.keys(formats).forEach((name) => {
          if (this.quill.scroll.query(name, Scope.INLINE) != null) {
            this.quill.format(name, false, Quill.sources.USER);
          }
        });
      } else {
        this.quill.removeFormat(range2.index, range2.length, Quill.sources.USER);
      }
    },
    direction(value) {
      const {
        align
      } = this.quill.getFormat();
      if (value === "rtl" && align == null) {
        this.quill.format("align", "right", Quill.sources.USER);
      } else if (!value && align === "right") {
        this.quill.format("align", false, Quill.sources.USER);
      }
      this.quill.format("direction", value, Quill.sources.USER);
    },
    indent(value) {
      const range2 = this.quill.getSelection();
      const formats = this.quill.getFormat(range2);
      const indent = parseInt(formats.indent || 0, 10);
      if (value === "+1" || value === "-1") {
        let modifier = value === "+1" ? 1 : -1;
        if (formats.direction === "rtl") modifier *= -1;
        this.quill.format("indent", indent + modifier, Quill.sources.USER);
      }
    },
    link(value) {
      if (value === true) {
        value = prompt("Enter link URL:");
      }
      this.quill.format("link", value, Quill.sources.USER);
    },
    list(value) {
      const range2 = this.quill.getSelection();
      const formats = this.quill.getFormat(range2);
      if (value === "check") {
        if (formats.list === "checked" || formats.list === "unchecked") {
          this.quill.format("list", false, Quill.sources.USER);
        } else {
          this.quill.format("list", "unchecked", Quill.sources.USER);
        }
      } else {
        this.quill.format("list", value, Quill.sources.USER);
      }
    }
  }
};

// node_modules/quill/ui/icons.js
var alignLeftIcon = '<svg viewbox="0 0 18 18"><line class="ql-stroke" x1="3" x2="15" y1="9" y2="9"/><line class="ql-stroke" x1="3" x2="13" y1="14" y2="14"/><line class="ql-stroke" x1="3" x2="9" y1="4" y2="4"/></svg>';
var alignCenterIcon = '<svg viewbox="0 0 18 18"><line class="ql-stroke" x1="15" x2="3" y1="9" y2="9"/><line class="ql-stroke" x1="14" x2="4" y1="14" y2="14"/><line class="ql-stroke" x1="12" x2="6" y1="4" y2="4"/></svg>';
var alignRightIcon = '<svg viewbox="0 0 18 18"><line class="ql-stroke" x1="15" x2="3" y1="9" y2="9"/><line class="ql-stroke" x1="15" x2="5" y1="14" y2="14"/><line class="ql-stroke" x1="15" x2="9" y1="4" y2="4"/></svg>';
var alignJustifyIcon = '<svg viewbox="0 0 18 18"><line class="ql-stroke" x1="15" x2="3" y1="9" y2="9"/><line class="ql-stroke" x1="15" x2="3" y1="14" y2="14"/><line class="ql-stroke" x1="15" x2="3" y1="4" y2="4"/></svg>';
var backgroundIcon = '<svg viewbox="0 0 18 18"><g class="ql-fill ql-color-label"><polygon points="6 6.868 6 6 5 6 5 7 5.942 7 6 6.868"/><rect height="1" width="1" x="4" y="4"/><polygon points="6.817 5 6 5 6 6 6.38 6 6.817 5"/><rect height="1" width="1" x="2" y="6"/><rect height="1" width="1" x="3" y="5"/><rect height="1" width="1" x="4" y="7"/><polygon points="4 11.439 4 11 3 11 3 12 3.755 12 4 11.439"/><rect height="1" width="1" x="2" y="12"/><rect height="1" width="1" x="2" y="9"/><rect height="1" width="1" x="2" y="15"/><polygon points="4.63 10 4 10 4 11 4.192 11 4.63 10"/><rect height="1" width="1" x="3" y="8"/><path d="M10.832,4.2L11,4.582V4H10.708A1.948,1.948,0,0,1,10.832,4.2Z"/><path d="M7,4.582L7.168,4.2A1.929,1.929,0,0,1,7.292,4H7V4.582Z"/><path d="M8,13H7.683l-0.351.8a1.933,1.933,0,0,1-.124.2H8V13Z"/><rect height="1" width="1" x="12" y="2"/><rect height="1" width="1" x="11" y="3"/><path d="M9,3H8V3.282A1.985,1.985,0,0,1,9,3Z"/><rect height="1" width="1" x="2" y="3"/><rect height="1" width="1" x="6" y="2"/><rect height="1" width="1" x="3" y="2"/><rect height="1" width="1" x="5" y="3"/><rect height="1" width="1" x="9" y="2"/><rect height="1" width="1" x="15" y="14"/><polygon points="13.447 10.174 13.469 10.225 13.472 10.232 13.808 11 14 11 14 10 13.37 10 13.447 10.174"/><rect height="1" width="1" x="13" y="7"/><rect height="1" width="1" x="15" y="5"/><rect height="1" width="1" x="14" y="6"/><rect height="1" width="1" x="15" y="8"/><rect height="1" width="1" x="14" y="9"/><path d="M3.775,14H3v1H4V14.314A1.97,1.97,0,0,1,3.775,14Z"/><rect height="1" width="1" x="14" y="3"/><polygon points="12 6.868 12 6 11.62 6 12 6.868"/><rect height="1" width="1" x="15" y="2"/><rect height="1" width="1" x="12" y="5"/><rect height="1" width="1" x="13" y="4"/><polygon points="12.933 9 13 9 13 8 12.495 8 12.933 9"/><rect height="1" width="1" x="9" y="14"/><rect height="1" width="1" x="8" y="15"/><path d="M6,14.926V15H7V14.316A1.993,1.993,0,0,1,6,14.926Z"/><rect height="1" width="1" x="5" y="15"/><path d="M10.668,13.8L10.317,13H10v1h0.792A1.947,1.947,0,0,1,10.668,13.8Z"/><rect height="1" width="1" x="11" y="15"/><path d="M14.332,12.2a1.99,1.99,0,0,1,.166.8H15V12H14.245Z"/><rect height="1" width="1" x="14" y="15"/><rect height="1" width="1" x="15" y="11"/></g><polyline class="ql-stroke" points="5.5 13 9 5 12.5 13"/><line class="ql-stroke" x1="11.63" x2="6.38" y1="11" y2="11"/></svg>';
var blockquoteIcon = '<svg viewbox="0 0 18 18"><rect class="ql-fill ql-stroke" height="3" width="3" x="4" y="5"/><rect class="ql-fill ql-stroke" height="3" width="3" x="11" y="5"/><path class="ql-even ql-fill ql-stroke" d="M7,8c0,4.031-3,5-3,5"/><path class="ql-even ql-fill ql-stroke" d="M14,8c0,4.031-3,5-3,5"/></svg>';
var boldIcon = '<svg viewbox="0 0 18 18"><path class="ql-stroke" d="M5,4H9.5A2.5,2.5,0,0,1,12,6.5v0A2.5,2.5,0,0,1,9.5,9H5A0,0,0,0,1,5,9V4A0,0,0,0,1,5,4Z"/><path class="ql-stroke" d="M5,9h5.5A2.5,2.5,0,0,1,13,11.5v0A2.5,2.5,0,0,1,10.5,14H5a0,0,0,0,1,0,0V9A0,0,0,0,1,5,9Z"/></svg>';
var cleanIcon = '<svg class="" viewbox="0 0 18 18"><line class="ql-stroke" x1="5" x2="13" y1="3" y2="3"/><line class="ql-stroke" x1="6" x2="9.35" y1="12" y2="3"/><line class="ql-stroke" x1="11" x2="15" y1="11" y2="15"/><line class="ql-stroke" x1="15" x2="11" y1="11" y2="15"/><rect class="ql-fill" height="1" rx="0.5" ry="0.5" width="7" x="2" y="14"/></svg>';
var codeIcon = '<svg viewbox="0 0 18 18"><polyline class="ql-even ql-stroke" points="5 7 3 9 5 11"/><polyline class="ql-even ql-stroke" points="13 7 15 9 13 11"/><line class="ql-stroke" x1="10" x2="8" y1="5" y2="13"/></svg>';
var colorIcon = '<svg viewbox="0 0 18 18"><line class="ql-color-label ql-stroke ql-transparent" x1="3" x2="15" y1="15" y2="15"/><polyline class="ql-stroke" points="5.5 11 9 3 12.5 11"/><line class="ql-stroke" x1="11.63" x2="6.38" y1="9" y2="9"/></svg>';
var directionLeftToRightIcon = '<svg viewbox="0 0 18 18"><polygon class="ql-stroke ql-fill" points="3 11 5 9 3 7 3 11"/><line class="ql-stroke ql-fill" x1="15" x2="11" y1="4" y2="4"/><path class="ql-fill" d="M11,3a3,3,0,0,0,0,6h1V3H11Z"/><rect class="ql-fill" height="11" width="1" x="11" y="4"/><rect class="ql-fill" height="11" width="1" x="13" y="4"/></svg>';
var directionRightToLeftIcon = '<svg viewbox="0 0 18 18"><polygon class="ql-stroke ql-fill" points="15 12 13 10 15 8 15 12"/><line class="ql-stroke ql-fill" x1="9" x2="5" y1="4" y2="4"/><path class="ql-fill" d="M5,3A3,3,0,0,0,5,9H6V3H5Z"/><rect class="ql-fill" height="11" width="1" x="5" y="4"/><rect class="ql-fill" height="11" width="1" x="7" y="4"/></svg>';
var formulaIcon = '<svg viewbox="0 0 18 18"><path class="ql-fill" d="M11.759,2.482a2.561,2.561,0,0,0-3.53.607A7.656,7.656,0,0,0,6.8,6.2C6.109,9.188,5.275,14.677,4.15,14.927a1.545,1.545,0,0,0-1.3-.933A0.922,0.922,0,0,0,2,15.036S1.954,16,4.119,16s3.091-2.691,3.7-5.553c0.177-.826.36-1.726,0.554-2.6L8.775,6.2c0.381-1.421.807-2.521,1.306-2.676a1.014,1.014,0,0,0,1.02.56A0.966,0.966,0,0,0,11.759,2.482Z"/><rect class="ql-fill" height="1.6" rx="0.8" ry="0.8" width="5" x="5.15" y="6.2"/><path class="ql-fill" d="M13.663,12.027a1.662,1.662,0,0,1,.266-0.276q0.193,0.069.456,0.138a2.1,2.1,0,0,0,.535.069,1.075,1.075,0,0,0,.767-0.3,1.044,1.044,0,0,0,.314-0.8,0.84,0.84,0,0,0-.238-0.619,0.8,0.8,0,0,0-.594-0.239,1.154,1.154,0,0,0-.781.3,4.607,4.607,0,0,0-.781,1q-0.091.15-.218,0.346l-0.246.38c-0.068-.288-0.137-0.582-0.212-0.885-0.459-1.847-2.494-.984-2.941-0.8-0.482.2-.353,0.647-0.094,0.529a0.869,0.869,0,0,1,1.281.585c0.217,0.751.377,1.436,0.527,2.038a5.688,5.688,0,0,1-.362.467,2.69,2.69,0,0,1-.264.271q-0.221-.08-0.471-0.147a2.029,2.029,0,0,0-.522-0.066,1.079,1.079,0,0,0-.768.3A1.058,1.058,0,0,0,9,15.131a0.82,0.82,0,0,0,.832.852,1.134,1.134,0,0,0,.787-0.3,5.11,5.11,0,0,0,.776-0.993q0.141-.219.215-0.34c0.046-.076.122-0.194,0.223-0.346a2.786,2.786,0,0,0,.918,1.726,2.582,2.582,0,0,0,2.376-.185c0.317-.181.212-0.565,0-0.494A0.807,0.807,0,0,1,14.176,15a5.159,5.159,0,0,1-.913-2.446l0,0Q13.487,12.24,13.663,12.027Z"/></svg>';
var headerIcon = '<svg viewBox="0 0 18 18"><path class="ql-fill" d="M10,4V14a1,1,0,0,1-2,0V10H3v4a1,1,0,0,1-2,0V4A1,1,0,0,1,3,4V8H8V4a1,1,0,0,1,2,0Zm6.06787,9.209H14.98975V7.59863a.54085.54085,0,0,0-.605-.60547h-.62744a1.01119,1.01119,0,0,0-.748.29688L11.645,8.56641a.5435.5435,0,0,0-.022.8584l.28613.30762a.53861.53861,0,0,0,.84717.0332l.09912-.08789a1.2137,1.2137,0,0,0,.2417-.35254h.02246s-.01123.30859-.01123.60547V13.209H12.041a.54085.54085,0,0,0-.605.60547v.43945a.54085.54085,0,0,0,.605.60547h4.02686a.54085.54085,0,0,0,.605-.60547v-.43945A.54085.54085,0,0,0,16.06787,13.209Z"/></svg>';
var header2Icon = '<svg viewBox="0 0 18 18"><path class="ql-fill" d="M16.73975,13.81445v.43945a.54085.54085,0,0,1-.605.60547H11.855a.58392.58392,0,0,1-.64893-.60547V14.0127c0-2.90527,3.39941-3.42187,3.39941-4.55469a.77675.77675,0,0,0-.84717-.78125,1.17684,1.17684,0,0,0-.83594.38477c-.2749.26367-.561.374-.85791.13184l-.4292-.34082c-.30811-.24219-.38525-.51758-.1543-.81445a2.97155,2.97155,0,0,1,2.45361-1.17676,2.45393,2.45393,0,0,1,2.68408,2.40918c0,2.45312-3.1792,2.92676-3.27832,3.93848h2.79443A.54085.54085,0,0,1,16.73975,13.81445ZM9,3A.99974.99974,0,0,0,8,4V8H3V4A1,1,0,0,0,1,4V14a1,1,0,0,0,2,0V10H8v4a1,1,0,0,0,2,0V4A.99974.99974,0,0,0,9,3Z"/></svg>';
var header3Icon = '<svg viewBox="0 0 18 18"><path class="ql-fill" d="M16.65186,12.30664a2.6742,2.6742,0,0,1-2.915,2.68457,3.96592,3.96592,0,0,1-2.25537-.6709.56007.56007,0,0,1-.13232-.83594L11.64648,13c.209-.34082.48389-.36328.82471-.1543a2.32654,2.32654,0,0,0,1.12256.33008c.71484,0,1.12207-.35156,1.12207-.78125,0-.61523-.61621-.86816-1.46338-.86816H13.2085a.65159.65159,0,0,1-.68213-.41895l-.05518-.10937a.67114.67114,0,0,1,.14307-.78125l.71533-.86914a8.55289,8.55289,0,0,1,.68213-.7373V8.58887a3.93913,3.93913,0,0,1-.748.05469H11.9873a.54085.54085,0,0,1-.605-.60547V7.59863a.54085.54085,0,0,1,.605-.60547h3.75146a.53773.53773,0,0,1,.60547.59375v.17676a1.03723,1.03723,0,0,1-.27539.748L14.74854,10.0293A2.31132,2.31132,0,0,1,16.65186,12.30664ZM9,3A.99974.99974,0,0,0,8,4V8H3V4A1,1,0,0,0,1,4V14a1,1,0,0,0,2,0V10H8v4a1,1,0,0,0,2,0V4A.99974.99974,0,0,0,9,3Z"/></svg>';
var header4Icon = '<svg viewBox="0 0 18 18"><path class="ql-fill" d="M10,4V14a1,1,0,0,1-2,0V10H3v4a1,1,0,0,1-2,0V4A1,1,0,0,1,3,4V8H8V4a1,1,0,0,1,2,0Zm7.05371,7.96582v.38477c0,.39648-.165.60547-.46191.60547h-.47314v1.29785a.54085.54085,0,0,1-.605.60547h-.69336a.54085.54085,0,0,1-.605-.60547V12.95605H11.333a.5412.5412,0,0,1-.60547-.60547v-.15332a1.199,1.199,0,0,1,.22021-.748l2.56348-4.05957a.7819.7819,0,0,1,.72607-.39648h1.27637a.54085.54085,0,0,1,.605.60547v3.7627h.33008A.54055.54055,0,0,1,17.05371,11.96582ZM14.28125,8.7207h-.022a4.18969,4.18969,0,0,1-.38525.81348l-1.188,1.80469v.02246h1.5293V9.60059A7.04058,7.04058,0,0,1,14.28125,8.7207Z"/></svg>';
var header5Icon = '<svg viewBox="0 0 18 18"><path class="ql-fill" d="M16.74023,12.18555a2.75131,2.75131,0,0,1-2.91553,2.80566,3.908,3.908,0,0,1-2.25537-.68164.54809.54809,0,0,1-.13184-.8252L11.73438,13c.209-.34082.48389-.36328.8252-.1543a2.23757,2.23757,0,0,0,1.1001.33008,1.01827,1.01827,0,0,0,1.1001-.96777c0-.61621-.53906-.97949-1.25439-.97949a2.15554,2.15554,0,0,0-.64893.09961,1.15209,1.15209,0,0,1-.814.01074l-.12109-.04395a.64116.64116,0,0,1-.45117-.71484l.231-3.00391a.56666.56666,0,0,1,.62744-.583H15.541a.54085.54085,0,0,1,.605.60547v.43945a.54085.54085,0,0,1-.605.60547H13.41748l-.04395.72559a1.29306,1.29306,0,0,1-.04395.30859h.022a2.39776,2.39776,0,0,1,.57227-.07715A2.53266,2.53266,0,0,1,16.74023,12.18555ZM9,3A.99974.99974,0,0,0,8,4V8H3V4A1,1,0,0,0,1,4V14a1,1,0,0,0,2,0V10H8v4a1,1,0,0,0,2,0V4A.99974.99974,0,0,0,9,3Z"/></svg>';
var header6Icon = '<svg viewBox="0 0 18 18"><path class="ql-fill" d="M14.51758,9.64453a1.85627,1.85627,0,0,0-1.24316.38477H13.252a1.73532,1.73532,0,0,1,1.72754-1.4082,2.66491,2.66491,0,0,1,.5498.06641c.35254.05469.57227.01074.70508-.40723l.16406-.5166a.53393.53393,0,0,0-.373-.75977,4.83723,4.83723,0,0,0-1.17773-.14258c-2.43164,0-3.7627,2.17773-3.7627,4.43359,0,2.47559,1.60645,3.69629,3.19043,3.69629A2.70585,2.70585,0,0,0,16.96,12.19727,2.43861,2.43861,0,0,0,14.51758,9.64453Zm-.23047,3.58691c-.67187,0-1.22168-.81445-1.22168-1.45215,0-.47363.30762-.583.72559-.583.96875,0,1.27734.59375,1.27734,1.12207A.82182.82182,0,0,1,14.28711,13.23145ZM10,4V14a1,1,0,0,1-2,0V10H3v4a1,1,0,0,1-2,0V4A1,1,0,0,1,3,4V8H8V4a1,1,0,0,1,2,0Z"/></svg>';
var italicIcon = '<svg viewbox="0 0 18 18"><line class="ql-stroke" x1="7" x2="13" y1="4" y2="4"/><line class="ql-stroke" x1="5" x2="11" y1="14" y2="14"/><line class="ql-stroke" x1="8" x2="10" y1="14" y2="4"/></svg>';
var imageIcon = '<svg viewbox="0 0 18 18"><rect class="ql-stroke" height="10" width="12" x="3" y="4"/><circle class="ql-fill" cx="6" cy="7" r="1"/><polyline class="ql-even ql-fill" points="5 12 5 11 7 9 8 10 11 7 13 9 13 12 5 12"/></svg>';
var indentIcon = '<svg viewbox="0 0 18 18"><line class="ql-stroke" x1="3" x2="15" y1="14" y2="14"/><line class="ql-stroke" x1="3" x2="15" y1="4" y2="4"/><line class="ql-stroke" x1="9" x2="15" y1="9" y2="9"/><polyline class="ql-fill ql-stroke" points="3 7 3 11 5 9 3 7"/></svg>';
var outdentIcon = '<svg viewbox="0 0 18 18"><line class="ql-stroke" x1="3" x2="15" y1="14" y2="14"/><line class="ql-stroke" x1="3" x2="15" y1="4" y2="4"/><line class="ql-stroke" x1="9" x2="15" y1="9" y2="9"/><polyline class="ql-stroke" points="5 7 5 11 3 9 5 7"/></svg>';
var linkIcon = '<svg viewbox="0 0 18 18"><line class="ql-stroke" x1="7" x2="11" y1="7" y2="11"/><path class="ql-even ql-stroke" d="M8.9,4.577a3.476,3.476,0,0,1,.36,4.679A3.476,3.476,0,0,1,4.577,8.9C3.185,7.5,2.035,6.4,4.217,4.217S7.5,3.185,8.9,4.577Z"/><path class="ql-even ql-stroke" d="M13.423,9.1a3.476,3.476,0,0,0-4.679-.36,3.476,3.476,0,0,0,.36,4.679c1.392,1.392,2.5,2.542,4.679.36S14.815,10.5,13.423,9.1Z"/></svg>';
var listBulletIcon = '<svg viewbox="0 0 18 18"><line class="ql-stroke" x1="6" x2="15" y1="4" y2="4"/><line class="ql-stroke" x1="6" x2="15" y1="9" y2="9"/><line class="ql-stroke" x1="6" x2="15" y1="14" y2="14"/><line class="ql-stroke" x1="3" x2="3" y1="4" y2="4"/><line class="ql-stroke" x1="3" x2="3" y1="9" y2="9"/><line class="ql-stroke" x1="3" x2="3" y1="14" y2="14"/></svg>';
var listCheckIcon = '<svg class="" viewbox="0 0 18 18"><line class="ql-stroke" x1="9" x2="15" y1="4" y2="4"/><polyline class="ql-stroke" points="3 4 4 5 6 3"/><line class="ql-stroke" x1="9" x2="15" y1="14" y2="14"/><polyline class="ql-stroke" points="3 14 4 15 6 13"/><line class="ql-stroke" x1="9" x2="15" y1="9" y2="9"/><polyline class="ql-stroke" points="3 9 4 10 6 8"/></svg>';
var listOrderedIcon = '<svg viewbox="0 0 18 18"><line class="ql-stroke" x1="7" x2="15" y1="4" y2="4"/><line class="ql-stroke" x1="7" x2="15" y1="9" y2="9"/><line class="ql-stroke" x1="7" x2="15" y1="14" y2="14"/><line class="ql-stroke ql-thin" x1="2.5" x2="4.5" y1="5.5" y2="5.5"/><path class="ql-fill" d="M3.5,6A0.5,0.5,0,0,1,3,5.5V3.085l-0.276.138A0.5,0.5,0,0,1,2.053,3c-0.124-.247-0.023-0.324.224-0.447l1-.5A0.5,0.5,0,0,1,4,2.5v3A0.5,0.5,0,0,1,3.5,6Z"/><path class="ql-stroke ql-thin" d="M4.5,10.5h-2c0-.234,1.85-1.076,1.85-2.234A0.959,0.959,0,0,0,2.5,8.156"/><path class="ql-stroke ql-thin" d="M2.5,14.846a0.959,0.959,0,0,0,1.85-.109A0.7,0.7,0,0,0,3.75,14a0.688,0.688,0,0,0,.6-0.736,0.959,0.959,0,0,0-1.85-.109"/></svg>';
var subscriptIcon = '<svg viewbox="0 0 18 18"><path class="ql-fill" d="M15.5,15H13.861a3.858,3.858,0,0,0,1.914-2.975,1.8,1.8,0,0,0-1.6-1.751A1.921,1.921,0,0,0,12.021,11.7a0.50013,0.50013,0,1,0,.957.291h0a0.914,0.914,0,0,1,1.053-.725,0.81,0.81,0,0,1,.744.762c0,1.076-1.16971,1.86982-1.93971,2.43082A1.45639,1.45639,0,0,0,12,15.5a0.5,0.5,0,0,0,.5.5h3A0.5,0.5,0,0,0,15.5,15Z"/><path class="ql-fill" d="M9.65,5.241a1,1,0,0,0-1.409.108L6,7.964,3.759,5.349A1,1,0,0,0,2.192,6.59178Q2.21541,6.6213,2.241,6.649L4.684,9.5,2.241,12.35A1,1,0,0,0,3.71,13.70722q0.02557-.02768.049-0.05722L6,11.036,8.241,13.65a1,1,0,1,0,1.567-1.24277Q9.78459,12.3777,9.759,12.35L7.316,9.5,9.759,6.651A1,1,0,0,0,9.65,5.241Z"/></svg>';
var superscriptIcon = '<svg viewbox="0 0 18 18"><path class="ql-fill" d="M15.5,7H13.861a4.015,4.015,0,0,0,1.914-2.975,1.8,1.8,0,0,0-1.6-1.751A1.922,1.922,0,0,0,12.021,3.7a0.5,0.5,0,1,0,.957.291,0.917,0.917,0,0,1,1.053-.725,0.81,0.81,0,0,1,.744.762c0,1.077-1.164,1.925-1.934,2.486A1.423,1.423,0,0,0,12,7.5a0.5,0.5,0,0,0,.5.5h3A0.5,0.5,0,0,0,15.5,7Z"/><path class="ql-fill" d="M9.651,5.241a1,1,0,0,0-1.41.108L6,7.964,3.759,5.349a1,1,0,1,0-1.519,1.3L4.683,9.5,2.241,12.35a1,1,0,1,0,1.519,1.3L6,11.036,8.241,13.65a1,1,0,0,0,1.519-1.3L7.317,9.5,9.759,6.651A1,1,0,0,0,9.651,5.241Z"/></svg>';
var strikeIcon = '<svg viewbox="0 0 18 18"><line class="ql-stroke ql-thin" x1="15.5" x2="2.5" y1="8.5" y2="9.5"/><path class="ql-fill" d="M9.007,8C6.542,7.791,6,7.519,6,6.5,6,5.792,7.283,5,9,5c1.571,0,2.765.679,2.969,1.309a1,1,0,0,0,1.9-.617C13.356,4.106,11.354,3,9,3,6.2,3,4,4.538,4,6.5a3.2,3.2,0,0,0,.5,1.843Z"/><path class="ql-fill" d="M8.984,10C11.457,10.208,12,10.479,12,11.5c0,0.708-1.283,1.5-3,1.5-1.571,0-2.765-.679-2.969-1.309a1,1,0,1,0-1.9.617C4.644,13.894,6.646,15,9,15c2.8,0,5-1.538,5-3.5a3.2,3.2,0,0,0-.5-1.843Z"/></svg>';
var tableIcon = '<svg viewbox="0 0 18 18"><rect class="ql-stroke" height="12" width="12" x="3" y="3"/><rect class="ql-fill" height="2" width="3" x="5" y="5"/><rect class="ql-fill" height="2" width="4" x="9" y="5"/><g class="ql-fill ql-transparent"><rect height="2" width="3" x="5" y="8"/><rect height="2" width="4" x="9" y="8"/><rect height="2" width="3" x="5" y="11"/><rect height="2" width="4" x="9" y="11"/></g></svg>';
var underlineIcon = '<svg viewbox="0 0 18 18"><path class="ql-stroke" d="M5,3V9a4.012,4.012,0,0,0,4,4H9a4.012,4.012,0,0,0,4-4V3"/><rect class="ql-fill" height="1" rx="0.5" ry="0.5" width="12" x="3" y="15"/></svg>';
var videoIcon = '<svg viewbox="0 0 18 18"><rect class="ql-stroke" height="12" width="12" x="3" y="3"/><rect class="ql-fill" height="12" width="1" x="5" y="3"/><rect class="ql-fill" height="12" width="1" x="12" y="3"/><rect class="ql-fill" height="2" width="8" x="5" y="8"/><rect class="ql-fill" height="1" width="3" x="3" y="5"/><rect class="ql-fill" height="1" width="3" x="3" y="7"/><rect class="ql-fill" height="1" width="3" x="3" y="10"/><rect class="ql-fill" height="1" width="3" x="3" y="12"/><rect class="ql-fill" height="1" width="3" x="12" y="5"/><rect class="ql-fill" height="1" width="3" x="12" y="7"/><rect class="ql-fill" height="1" width="3" x="12" y="10"/><rect class="ql-fill" height="1" width="3" x="12" y="12"/></svg>';
var icons_default = {
  align: {
    "": alignLeftIcon,
    center: alignCenterIcon,
    right: alignRightIcon,
    justify: alignJustifyIcon
  },
  background: backgroundIcon,
  blockquote: blockquoteIcon,
  bold: boldIcon,
  clean: cleanIcon,
  code: codeIcon,
  "code-block": codeIcon,
  color: colorIcon,
  direction: {
    "": directionLeftToRightIcon,
    rtl: directionRightToLeftIcon
  },
  formula: formulaIcon,
  header: {
    "1": headerIcon,
    "2": header2Icon,
    "3": header3Icon,
    "4": header4Icon,
    "5": header5Icon,
    "6": header6Icon
  },
  italic: italicIcon,
  image: imageIcon,
  indent: {
    "+1": indentIcon,
    "-1": outdentIcon
  },
  link: linkIcon,
  list: {
    bullet: listBulletIcon,
    check: listCheckIcon,
    ordered: listOrderedIcon
  },
  script: {
    sub: subscriptIcon,
    super: superscriptIcon
  },
  strike: strikeIcon,
  table: tableIcon,
  underline: underlineIcon,
  video: videoIcon
};

// node_modules/quill/ui/picker.js
var DropdownIcon = '<svg viewbox="0 0 18 18"><polygon class="ql-stroke" points="7 11 9 13 11 11 7 11"/><polygon class="ql-stroke" points="7 7 9 5 11 7 7 7"/></svg>';
var optionsCounter = 0;
function toggleAriaAttribute(element, attribute) {
  element.setAttribute(attribute, `${!(element.getAttribute(attribute) === "true")}`);
}
var Picker = class {
  constructor(select) {
    this.select = select;
    this.container = document.createElement("span");
    this.buildPicker();
    this.select.style.display = "none";
    this.select.parentNode.insertBefore(this.container, this.select);
    this.label.addEventListener("mousedown", () => {
      this.togglePicker();
    });
    this.label.addEventListener("keydown", (event) => {
      switch (event.key) {
        case "Enter":
          this.togglePicker();
          break;
        case "Escape":
          this.escape();
          event.preventDefault();
          break;
        default:
      }
    });
    this.select.addEventListener("change", this.update.bind(this));
  }
  togglePicker() {
    this.container.classList.toggle("ql-expanded");
    toggleAriaAttribute(this.label, "aria-expanded");
    toggleAriaAttribute(this.options, "aria-hidden");
  }
  buildItem(option) {
    const item = document.createElement("span");
    item.tabIndex = "0";
    item.setAttribute("role", "button");
    item.classList.add("ql-picker-item");
    const value = option.getAttribute("value");
    if (value) {
      item.setAttribute("data-value", value);
    }
    if (option.textContent) {
      item.setAttribute("data-label", option.textContent);
    }
    item.addEventListener("click", () => {
      this.selectItem(item, true);
    });
    item.addEventListener("keydown", (event) => {
      switch (event.key) {
        case "Enter":
          this.selectItem(item, true);
          event.preventDefault();
          break;
        case "Escape":
          this.escape();
          event.preventDefault();
          break;
        default:
      }
    });
    return item;
  }
  buildLabel() {
    const label = document.createElement("span");
    label.classList.add("ql-picker-label");
    label.innerHTML = DropdownIcon;
    label.tabIndex = "0";
    label.setAttribute("role", "button");
    label.setAttribute("aria-expanded", "false");
    this.container.appendChild(label);
    return label;
  }
  buildOptions() {
    const options = document.createElement("span");
    options.classList.add("ql-picker-options");
    options.setAttribute("aria-hidden", "true");
    options.tabIndex = "-1";
    options.id = `ql-picker-options-${optionsCounter}`;
    optionsCounter += 1;
    this.label.setAttribute("aria-controls", options.id);
    this.options = options;
    Array.from(this.select.options).forEach((option) => {
      const item = this.buildItem(option);
      options.appendChild(item);
      if (option.selected === true) {
        this.selectItem(item);
      }
    });
    this.container.appendChild(options);
  }
  buildPicker() {
    Array.from(this.select.attributes).forEach((item) => {
      this.container.setAttribute(item.name, item.value);
    });
    this.container.classList.add("ql-picker");
    this.label = this.buildLabel();
    this.buildOptions();
  }
  escape() {
    this.close();
    setTimeout(() => this.label.focus(), 1);
  }
  close() {
    this.container.classList.remove("ql-expanded");
    this.label.setAttribute("aria-expanded", "false");
    this.options.setAttribute("aria-hidden", "true");
  }
  selectItem(item) {
    let trigger = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : false;
    const selected = this.container.querySelector(".ql-selected");
    if (item === selected) return;
    if (selected != null) {
      selected.classList.remove("ql-selected");
    }
    if (item == null) return;
    item.classList.add("ql-selected");
    this.select.selectedIndex = Array.from(item.parentNode.children).indexOf(item);
    if (item.hasAttribute("data-value")) {
      this.label.setAttribute("data-value", item.getAttribute("data-value"));
    } else {
      this.label.removeAttribute("data-value");
    }
    if (item.hasAttribute("data-label")) {
      this.label.setAttribute("data-label", item.getAttribute("data-label"));
    } else {
      this.label.removeAttribute("data-label");
    }
    if (trigger) {
      this.select.dispatchEvent(new Event("change"));
      this.close();
    }
  }
  update() {
    let option;
    if (this.select.selectedIndex > -1) {
      const item = (
        // @ts-expect-error Fix me later
        this.container.querySelector(".ql-picker-options").children[this.select.selectedIndex]
      );
      option = this.select.options[this.select.selectedIndex];
      this.selectItem(item);
    } else {
      this.selectItem(null);
    }
    const isActive = option != null && option !== this.select.querySelector("option[selected]");
    this.label.classList.toggle("ql-active", isActive);
  }
};
var picker_default = Picker;

// node_modules/quill/ui/color-picker.js
var ColorPicker = class extends picker_default {
  constructor(select, label) {
    super(select);
    this.label.innerHTML = label;
    this.container.classList.add("ql-color-picker");
    Array.from(this.container.querySelectorAll(".ql-picker-item")).slice(0, 7).forEach((item) => {
      item.classList.add("ql-primary");
    });
  }
  buildItem(option) {
    const item = super.buildItem(option);
    item.style.backgroundColor = option.getAttribute("value") || "";
    return item;
  }
  selectItem(item, trigger) {
    super.selectItem(item, trigger);
    const colorLabel = this.label.querySelector(".ql-color-label");
    const value = item ? item.getAttribute("data-value") || "" : "";
    if (colorLabel) {
      if (colorLabel.tagName === "line") {
        colorLabel.style.stroke = value;
      } else {
        colorLabel.style.fill = value;
      }
    }
  }
};
var color_picker_default = ColorPicker;

// node_modules/quill/ui/icon-picker.js
var IconPicker = class extends picker_default {
  constructor(select, icons) {
    super(select);
    this.container.classList.add("ql-icon-picker");
    Array.from(this.container.querySelectorAll(".ql-picker-item")).forEach((item) => {
      item.innerHTML = icons[item.getAttribute("data-value") || ""];
    });
    this.defaultItem = this.container.querySelector(".ql-selected");
    this.selectItem(this.defaultItem);
  }
  selectItem(target, trigger) {
    super.selectItem(target, trigger);
    const item = target || this.defaultItem;
    if (item != null) {
      if (this.label.innerHTML === item.innerHTML) return;
      this.label.innerHTML = item.innerHTML;
    }
  }
};
var icon_picker_default = IconPicker;

// node_modules/quill/ui/tooltip.js
var isScrollable = (el) => {
  const {
    overflowY
  } = getComputedStyle(el, null);
  return overflowY !== "visible" && overflowY !== "clip";
};
var Tooltip = class {
  constructor(quill, boundsContainer) {
    this.quill = quill;
    this.boundsContainer = boundsContainer || document.body;
    this.root = quill.addContainer("ql-tooltip");
    this.root.innerHTML = this.constructor.TEMPLATE;
    if (isScrollable(this.quill.root)) {
      this.quill.root.addEventListener("scroll", () => {
        this.root.style.marginTop = `${-1 * this.quill.root.scrollTop}px`;
      });
    }
    this.hide();
  }
  hide() {
    this.root.classList.add("ql-hidden");
  }
  position(reference) {
    const left = reference.left + reference.width / 2 - this.root.offsetWidth / 2;
    const top = reference.bottom + this.quill.root.scrollTop;
    this.root.style.left = `${left}px`;
    this.root.style.top = `${top}px`;
    this.root.classList.remove("ql-flip");
    const containerBounds = this.boundsContainer.getBoundingClientRect();
    const rootBounds = this.root.getBoundingClientRect();
    let shift = 0;
    if (rootBounds.right > containerBounds.right) {
      shift = containerBounds.right - rootBounds.right;
      this.root.style.left = `${left + shift}px`;
    }
    if (rootBounds.left < containerBounds.left) {
      shift = containerBounds.left - rootBounds.left;
      this.root.style.left = `${left + shift}px`;
    }
    if (rootBounds.bottom > containerBounds.bottom) {
      const height = rootBounds.bottom - rootBounds.top;
      const verticalShift = reference.bottom - reference.top + height;
      this.root.style.top = `${top - verticalShift}px`;
      this.root.classList.add("ql-flip");
    }
    return shift;
  }
  show() {
    this.root.classList.remove("ql-editing");
    this.root.classList.remove("ql-hidden");
  }
};
var tooltip_default = Tooltip;

// node_modules/quill/themes/base.js
var ALIGNS = [false, "center", "right", "justify"];
var COLORS = ["#000000", "#e60000", "#ff9900", "#ffff00", "#008a00", "#0066cc", "#9933ff", "#ffffff", "#facccc", "#ffebcc", "#ffffcc", "#cce8cc", "#cce0f5", "#ebd6ff", "#bbbbbb", "#f06666", "#ffc266", "#ffff66", "#66b966", "#66a3e0", "#c285ff", "#888888", "#a10000", "#b26b00", "#b2b200", "#006100", "#0047b2", "#6b24b2", "#444444", "#5c0000", "#663d00", "#666600", "#003700", "#002966", "#3d1466"];
var FONTS = [false, "serif", "monospace"];
var HEADERS = ["1", "2", "3", false];
var SIZES = ["small", false, "large", "huge"];
var BaseTheme = class extends theme_default {
  constructor(quill, options) {
    super(quill, options);
    const listener = (e) => {
      if (!document.body.contains(quill.root)) {
        document.body.removeEventListener("click", listener);
        return;
      }
      if (this.tooltip != null && // @ts-expect-error
      !this.tooltip.root.contains(e.target) && // @ts-expect-error
      document.activeElement !== this.tooltip.textbox && !this.quill.hasFocus()) {
        this.tooltip.hide();
      }
      if (this.pickers != null) {
        this.pickers.forEach((picker) => {
          if (!picker.container.contains(e.target)) {
            picker.close();
          }
        });
      }
    };
    quill.emitter.listenDOM("click", document.body, listener);
  }
  addModule(name) {
    const module2 = super.addModule(name);
    if (name === "toolbar") {
      this.extendToolbar(module2);
    }
    return module2;
  }
  buildButtons(buttons, icons) {
    Array.from(buttons).forEach((button) => {
      const className = button.getAttribute("class") || "";
      className.split(/\s+/).forEach((name) => {
        if (!name.startsWith("ql-")) return;
        name = name.slice("ql-".length);
        if (icons[name] == null) return;
        if (name === "direction") {
          button.innerHTML = icons[name][""] + icons[name].rtl;
        } else if (typeof icons[name] === "string") {
          button.innerHTML = icons[name];
        } else {
          const value = button.value || "";
          if (value != null && icons[name][value]) {
            button.innerHTML = icons[name][value];
          }
        }
      });
    });
  }
  buildPickers(selects, icons) {
    this.pickers = Array.from(selects).map((select) => {
      if (select.classList.contains("ql-align")) {
        if (select.querySelector("option") == null) {
          fillSelect(select, ALIGNS);
        }
        if (typeof icons.align === "object") {
          return new icon_picker_default(select, icons.align);
        }
      }
      if (select.classList.contains("ql-background") || select.classList.contains("ql-color")) {
        const format = select.classList.contains("ql-background") ? "background" : "color";
        if (select.querySelector("option") == null) {
          fillSelect(select, COLORS, format === "background" ? "#ffffff" : "#000000");
        }
        return new color_picker_default(select, icons[format]);
      }
      if (select.querySelector("option") == null) {
        if (select.classList.contains("ql-font")) {
          fillSelect(select, FONTS);
        } else if (select.classList.contains("ql-header")) {
          fillSelect(select, HEADERS);
        } else if (select.classList.contains("ql-size")) {
          fillSelect(select, SIZES);
        }
      }
      return new picker_default(select);
    });
    const update2 = () => {
      this.pickers.forEach((picker) => {
        picker.update();
      });
    };
    this.quill.on(emitter_default.events.EDITOR_CHANGE, update2);
  }
};
BaseTheme.DEFAULTS = merge_default({}, theme_default.DEFAULTS, {
  modules: {
    toolbar: {
      handlers: {
        formula() {
          this.quill.theme.tooltip.edit("formula");
        },
        image() {
          let fileInput = this.container.querySelector("input.ql-image[type=file]");
          if (fileInput == null) {
            fileInput = document.createElement("input");
            fileInput.setAttribute("type", "file");
            fileInput.setAttribute("accept", this.quill.uploader.options.mimetypes.join(", "));
            fileInput.classList.add("ql-image");
            fileInput.addEventListener("change", () => {
              const range2 = this.quill.getSelection(true);
              this.quill.uploader.upload(range2, fileInput.files);
              fileInput.value = "";
            });
            this.container.appendChild(fileInput);
          }
          fileInput.click();
        },
        video() {
          this.quill.theme.tooltip.edit("video");
        }
      }
    }
  }
});
var BaseTooltip = class extends tooltip_default {
  constructor(quill, boundsContainer) {
    super(quill, boundsContainer);
    this.textbox = this.root.querySelector('input[type="text"]');
    this.listen();
  }
  listen() {
    this.textbox.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        this.save();
        event.preventDefault();
      } else if (event.key === "Escape") {
        this.cancel();
        event.preventDefault();
      }
    });
  }
  cancel() {
    this.hide();
    this.restoreFocus();
  }
  edit() {
    let mode = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : "link";
    let preview = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : null;
    this.root.classList.remove("ql-hidden");
    this.root.classList.add("ql-editing");
    if (this.textbox == null) return;
    if (preview != null) {
      this.textbox.value = preview;
    } else if (mode !== this.root.getAttribute("data-mode")) {
      this.textbox.value = "";
    }
    const bounds = this.quill.getBounds(this.quill.selection.savedRange);
    if (bounds != null) {
      this.position(bounds);
    }
    this.textbox.select();
    this.textbox.setAttribute("placeholder", this.textbox.getAttribute(`data-${mode}`) || "");
    this.root.setAttribute("data-mode", mode);
  }
  restoreFocus() {
    this.quill.focus({
      preventScroll: true
    });
  }
  save() {
    let {
      value
    } = this.textbox;
    switch (this.root.getAttribute("data-mode")) {
      case "link": {
        const {
          scrollTop
        } = this.quill.root;
        if (this.linkRange) {
          this.quill.formatText(this.linkRange, "link", value, emitter_default.sources.USER);
          delete this.linkRange;
        } else {
          this.restoreFocus();
          this.quill.format("link", value, emitter_default.sources.USER);
        }
        this.quill.root.scrollTop = scrollTop;
        break;
      }
      case "video": {
        value = extractVideoUrl(value);
      }
      // eslint-disable-next-line no-fallthrough
      case "formula": {
        if (!value) break;
        const range2 = this.quill.getSelection(true);
        if (range2 != null) {
          const index = range2.index + range2.length;
          this.quill.insertEmbed(
            index,
            // @ts-expect-error Fix me later
            this.root.getAttribute("data-mode"),
            value,
            emitter_default.sources.USER
          );
          if (this.root.getAttribute("data-mode") === "formula") {
            this.quill.insertText(index + 1, " ", emitter_default.sources.USER);
          }
          this.quill.setSelection(index + 2, emitter_default.sources.USER);
        }
        break;
      }
      default:
    }
    this.textbox.value = "";
    this.hide();
  }
};
function extractVideoUrl(url) {
  let match2 = url.match(/^(?:(https?):\/\/)?(?:(?:www|m)\.)?youtube\.com\/watch.*v=([a-zA-Z0-9_-]+)/) || url.match(/^(?:(https?):\/\/)?(?:(?:www|m)\.)?youtu\.be\/([a-zA-Z0-9_-]+)/);
  if (match2) {
    return `${match2[1] || "https"}://www.youtube.com/embed/${match2[2]}?showinfo=0`;
  }
  if (match2 = url.match(/^(?:(https?):\/\/)?(?:www\.)?vimeo\.com\/(\d+)/)) {
    return `${match2[1] || "https"}://player.vimeo.com/video/${match2[2]}/`;
  }
  return url;
}
function fillSelect(select, values2) {
  let defaultValue = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : false;
  values2.forEach((value) => {
    const option = document.createElement("option");
    if (value === defaultValue) {
      option.setAttribute("selected", "selected");
    } else {
      option.setAttribute("value", String(value));
    }
    select.appendChild(option);
  });
}

// node_modules/quill/themes/bubble.js
var TOOLBAR_CONFIG = [["bold", "italic", "link"], [{
  header: 1
}, {
  header: 2
}, "blockquote"]];
var BubbleTooltip = class extends BaseTooltip {
  static TEMPLATE = ['<span class="ql-tooltip-arrow"></span>', '<div class="ql-tooltip-editor">', '<input type="text" data-formula="e=mc^2" data-link="https://quilljs.com" data-video="Embed URL">', '<a class="ql-close"></a>', "</div>"].join("");
  constructor(quill, bounds) {
    super(quill, bounds);
    this.quill.on(emitter_default.events.EDITOR_CHANGE, (type, range2, oldRange, source) => {
      if (type !== emitter_default.events.SELECTION_CHANGE) return;
      if (range2 != null && range2.length > 0 && source === emitter_default.sources.USER) {
        this.show();
        this.root.style.left = "0px";
        this.root.style.width = "";
        this.root.style.width = `${this.root.offsetWidth}px`;
        const lines = this.quill.getLines(range2.index, range2.length);
        if (lines.length === 1) {
          const bounds2 = this.quill.getBounds(range2);
          if (bounds2 != null) {
            this.position(bounds2);
          }
        } else {
          const lastLine = lines[lines.length - 1];
          const index = this.quill.getIndex(lastLine);
          const length = Math.min(lastLine.length() - 1, range2.index + range2.length - index);
          const indexBounds = this.quill.getBounds(new Range(index, length));
          if (indexBounds != null) {
            this.position(indexBounds);
          }
        }
      } else if (document.activeElement !== this.textbox && this.quill.hasFocus()) {
        this.hide();
      }
    });
  }
  listen() {
    super.listen();
    this.root.querySelector(".ql-close").addEventListener("click", () => {
      this.root.classList.remove("ql-editing");
    });
    this.quill.on(emitter_default.events.SCROLL_OPTIMIZE, () => {
      setTimeout(() => {
        if (this.root.classList.contains("ql-hidden")) return;
        const range2 = this.quill.getSelection();
        if (range2 != null) {
          const bounds = this.quill.getBounds(range2);
          if (bounds != null) {
            this.position(bounds);
          }
        }
      }, 1);
    });
  }
  cancel() {
    this.show();
  }
  position(reference) {
    const shift = super.position(reference);
    const arrow = this.root.querySelector(".ql-tooltip-arrow");
    arrow.style.marginLeft = "";
    if (shift !== 0) {
      arrow.style.marginLeft = `${-1 * shift - arrow.offsetWidth / 2}px`;
    }
    return shift;
  }
};
var BubbleTheme = class extends BaseTheme {
  constructor(quill, options) {
    if (options.modules.toolbar != null && options.modules.toolbar.container == null) {
      options.modules.toolbar.container = TOOLBAR_CONFIG;
    }
    super(quill, options);
    this.quill.container.classList.add("ql-bubble");
  }
  extendToolbar(toolbar) {
    this.tooltip = new BubbleTooltip(this.quill, this.options.bounds);
    if (toolbar.container != null) {
      this.tooltip.root.appendChild(toolbar.container);
      this.buildButtons(toolbar.container.querySelectorAll("button"), icons_default);
      this.buildPickers(toolbar.container.querySelectorAll("select"), icons_default);
    }
  }
};
BubbleTheme.DEFAULTS = merge_default({}, BaseTheme.DEFAULTS, {
  modules: {
    toolbar: {
      handlers: {
        link(value) {
          if (!value) {
            this.quill.format("link", false, Quill.sources.USER);
          } else {
            this.quill.theme.tooltip.edit();
          }
        }
      }
    }
  }
});

// node_modules/quill/themes/snow.js
var TOOLBAR_CONFIG2 = [[{
  header: ["1", "2", "3", false]
}], ["bold", "italic", "underline", "link"], [{
  list: "ordered"
}, {
  list: "bullet"
}], ["clean"]];
var SnowTooltip = class extends BaseTooltip {
  static TEMPLATE = ['<a class="ql-preview" rel="noopener noreferrer" target="_blank" href="about:blank"></a>', '<input type="text" data-formula="e=mc^2" data-link="https://quilljs.com" data-video="Embed URL">', '<a class="ql-action"></a>', '<a class="ql-remove"></a>'].join("");
  preview = this.root.querySelector("a.ql-preview");
  listen() {
    super.listen();
    this.root.querySelector("a.ql-action").addEventListener("click", (event) => {
      if (this.root.classList.contains("ql-editing")) {
        this.save();
      } else {
        this.edit("link", this.preview.textContent);
      }
      event.preventDefault();
    });
    this.root.querySelector("a.ql-remove").addEventListener("click", (event) => {
      if (this.linkRange != null) {
        const range2 = this.linkRange;
        this.restoreFocus();
        this.quill.formatText(range2, "link", false, emitter_default.sources.USER);
        delete this.linkRange;
      }
      event.preventDefault();
      this.hide();
    });
    this.quill.on(emitter_default.events.SELECTION_CHANGE, (range2, oldRange, source) => {
      if (range2 == null) return;
      if (range2.length === 0 && source === emitter_default.sources.USER) {
        const [link, offset] = this.quill.scroll.descendant(Link, range2.index);
        if (link != null) {
          this.linkRange = new Range(range2.index - offset, link.length());
          const preview = Link.formats(link.domNode);
          this.preview.textContent = preview;
          this.preview.setAttribute("href", preview);
          this.show();
          const bounds = this.quill.getBounds(this.linkRange);
          if (bounds != null) {
            this.position(bounds);
          }
          return;
        }
      } else {
        delete this.linkRange;
      }
      this.hide();
    });
  }
  show() {
    super.show();
    this.root.removeAttribute("data-mode");
  }
};
var SnowTheme = class extends BaseTheme {
  constructor(quill, options) {
    if (options.modules.toolbar != null && options.modules.toolbar.container == null) {
      options.modules.toolbar.container = TOOLBAR_CONFIG2;
    }
    super(quill, options);
    this.quill.container.classList.add("ql-snow");
  }
  extendToolbar(toolbar) {
    if (toolbar.container != null) {
      toolbar.container.classList.add("ql-snow");
      this.buildButtons(toolbar.container.querySelectorAll("button"), icons_default);
      this.buildPickers(toolbar.container.querySelectorAll("select"), icons_default);
      this.tooltip = new SnowTooltip(this.quill, this.options.bounds);
      if (toolbar.container.querySelector(".ql-link")) {
        this.quill.keyboard.addBinding({
          key: "k",
          shortKey: true
        }, (_range, context) => {
          toolbar.handlers.link.call(toolbar, !context.format.link);
        });
      }
    }
  }
};
SnowTheme.DEFAULTS = merge_default({}, BaseTheme.DEFAULTS, {
  modules: {
    toolbar: {
      handlers: {
        link(value) {
          if (value) {
            const range2 = this.quill.getSelection();
            if (range2 == null || range2.length === 0) return;
            let preview = this.quill.getText(range2);
            if (/^\S+@\S+\.\S+$/.test(preview) && preview.indexOf("mailto:") !== 0) {
              preview = `mailto:${preview}`;
            }
            const {
              tooltip
            } = this.quill.theme;
            tooltip.edit("link", preview);
          } else {
            this.quill.format("link", false, Quill.sources.USER);
          }
        }
      }
    }
  }
});
var snow_default = SnowTheme;

// node_modules/quill/quill.js
core_default.register({
  "attributors/attribute/direction": DirectionAttribute,
  "attributors/class/align": AlignClass,
  "attributors/class/background": BackgroundClass,
  "attributors/class/color": ColorClass,
  "attributors/class/direction": DirectionClass,
  "attributors/class/font": FontClass,
  "attributors/class/size": SizeClass,
  "attributors/style/align": AlignStyle,
  "attributors/style/background": BackgroundStyle,
  "attributors/style/color": ColorStyle,
  "attributors/style/direction": DirectionStyle,
  "attributors/style/font": FontStyle,
  "attributors/style/size": SizeStyle
}, true);
core_default.register({
  "formats/align": AlignClass,
  "formats/direction": DirectionClass,
  "formats/indent": indent_default,
  "formats/background": BackgroundStyle,
  "formats/color": ColorStyle,
  "formats/font": FontClass,
  "formats/size": SizeClass,
  "formats/blockquote": blockquote_default,
  "formats/code-block": CodeBlock,
  "formats/header": header_default,
  "formats/list": ListItem,
  "formats/bold": bold_default,
  "formats/code": Code,
  "formats/italic": italic_default,
  "formats/link": Link,
  "formats/script": script_default,
  "formats/strike": strike_default,
  "formats/underline": underline_default,
  "formats/formula": formula_default,
  "formats/image": image_default,
  "formats/video": video_default,
  "modules/syntax": Syntax,
  "modules/table": table_default,
  "modules/toolbar": Toolbar,
  "themes/bubble": BubbleTheme,
  "themes/snow": snow_default,
  "ui/icons": icons_default,
  "ui/picker": picker_default,
  "ui/icon-picker": icon_picker_default,
  "ui/color-picker": color_picker_default,
  "ui/tooltip": tooltip_default
}, true);
var quill_default = core_default;
var export_AttributeMap = import_quill_delta9.AttributeMap;
var export_Delta = import_quill_delta9.default;
var export_Op = import_quill_delta9.Op;
var export_OpIterator = import_quill_delta9.OpIterator;
export {
  export_AttributeMap as AttributeMap,
  export_Delta as Delta,
  module_default as Module,
  export_Op as Op,
  export_OpIterator as OpIterator,
  parchment_exports as Parchment,
  Range,
  quill_default as default
};
/*! Bundled license information:

lodash-es/lodash.default.js:
  (**
   * @license
   * Lodash (Custom Build) <https://lodash.com/>
   * Build: `lodash modularize exports="es" -o ./`
   * Copyright OpenJS Foundation and other contributors <https://openjsf.org/>
   * Released under MIT license <https://lodash.com/license>
   * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
   * Copyright Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
   *)

lodash-es/lodash.js:
  (**
   * @license
   * Lodash (Custom Build) <https://lodash.com/>
   * Build: `lodash modularize exports="es" -o ./`
   * Copyright OpenJS Foundation and other contributors <https://openjsf.org/>
   * Released under MIT license <https://lodash.com/license>
   * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
   * Copyright Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
   *)
*/
//# sourceMappingURL=quill-FFADCBOX.js.map
