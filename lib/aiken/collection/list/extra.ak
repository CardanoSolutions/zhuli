////  This Source Code Form is subject to the terms of the Mozilla Public
////  License, v. 2.0. If a copy of the MPL was not distributed with this
////  file, You can obtain one at http://mozilla.org/MPL/2.0/.

/// Insert an element in a list at the given position.
pub fn insert(self: List<a>, ix: Int, elem: a) -> List<a> {
  when self is {
    [] -> [elem]
    [head, ..tail] ->
      if ix == 0 {
        [elem, head, ..tail]
      } else {
        [head, ..insert(tail, ix - 1, elem)]
      }
  }
}
