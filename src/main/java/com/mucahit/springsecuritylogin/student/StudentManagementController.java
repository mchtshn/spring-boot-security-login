package com.mucahit.springsecuritylogin.student;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "mucahit"),
            new Student(2, "ahmet"),
            new Student(3, "mehmet")
    );

    @GetMapping(path = "{studentId}")
    public List<Student> getAllStudents() {
        return STUDENTS;
    }

    @PostMapping
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    public void deleteStudent(@PathVariable("studentId") Integer studentId) {
        System.out.println("Deleted student "+studentId);
    }

    @PutMapping(path = "{studentId}")
    public void updateStudent(@PathVariable("studentId") Integer studentId,@RequestBody Student student) {
        System.out.println(String.format("%s %s",studentId,student));
    }
}
