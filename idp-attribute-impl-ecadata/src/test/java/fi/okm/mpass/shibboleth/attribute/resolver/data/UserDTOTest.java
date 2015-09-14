/*
 * The MIT License
 * Copyright (c) 2015 CSC - IT Center for Science, http://www.csc.fi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package fi.okm.mpass.shibboleth.attribute.resolver.data;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.google.gson.Gson;

/**
 * Unit testing for {@link UserDTO} using Gson.
 */
public class UserDTOTest {

    /**
     * Tests parsing of a single user data transfer object.
     */
    @Test
    public void test() {
        Gson gson = new Gson();
        String test =
                "{\"username\": \"OID1\", \"first_name\": \"John\", "
                + "\"last_name\": \"Doe\", \"roles\": "
                + "[{\"role\": \"teacher\", \"school\": \"12345\", \"group\": \"7C\"}], "
                + "\"attributes\": [{\"name\": \"google\", "
                + "\"value\": \"11XxjGZOeAyNqwTdq0Xec9ydDhYoq5CHrTQXHHSfGWM=\"}]}";
        UserDTO user = gson.fromJson(test, UserDTO.class);
        Assert.assertEquals(user.getUsername(), "OID1");
        Assert.assertEquals(user.getFirstName(), "John");
        Assert.assertEquals(user.getLastName(), "Doe");
        Assert.assertEquals(user.getRoles().length, 1);
        Assert.assertEquals(user.getRoles()[0].getRole(), "teacher");
        Assert.assertEquals(user.getRoles()[0].getSchool(), "12345");
        Assert.assertEquals(user.getRoles()[0].getGroup(), "7C");
        Assert.assertEquals(user.getAttributes().length, 1);
        Assert.assertEquals(user.getAttributes()[0].getName(), "google");
        Assert.assertEquals(user.getAttributes()[0].getValue(), "11XxjGZOeAyNqwTdq0Xec9ydDhYoq5CHrTQXHHSfGWM=");
    }
}