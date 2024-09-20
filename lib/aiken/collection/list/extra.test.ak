////  This Source Code Form is subject to the terms of the Mozilla Public
////  License, v. 2.0. If a copy of the MPL was not distributed with this
////  file, You can obtain one at http://mozilla.org/MPL/2.0/.

use aiken/collection/list/extra.{insert}

test insert_examples() {
  and {
    (insert([], 0, elem: 0) == [0])?,
    (insert([], 2, elem: 0) == [0])?,
    (insert([1, 2], 0, elem: 0) == [0, 1, 2])?,
    (insert([1, 2], 2, elem: 0) == [1, 2, 0])?,
    (insert([1, 2], -1, elem: 0) == [1, 2, 0])?,
  }
}
